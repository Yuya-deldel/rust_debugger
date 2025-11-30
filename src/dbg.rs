use crate::helper::DynError;
use nix::{
    libc::{personality, user_regs_struct},
    sys::{
        personality::{self, Persona},
        ptrace,
        wait::{WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, execvp, fork},
};
use std::ffi::{c_void, CString};

// デバッガの情報
pub struct DbgInfo {
    pid: Pid,       // process id
    brk_addr: Option<*mut c_void>,      // break point のアドレス
    brk_val: i64,           // break point を設定したメモリの元の値
    filename: String,       // 実行ファイル    
}

// MyDebug<Running> -> 子プロセス実行中, MyDebug<NotRunning> -> 子プロセス停止中
pub struct MyDebug<T> {
    info: Box<DbgInfo>,
    _state: T,
}
// size が 0 の型 (phantom type): 実行時には現れないが型検査時に現れる
pub struct Running;
pub struct NotRunning;

pub enum State {
    Running(MyDebug<Running>),
    NotRunning(MyDebug<NotRunning>),
    Exit,
}

// 常に呼び出せる method
impl<T> MyDebug<T> {
    // break point のアドレスを設定、成功したら true を返す
    fn set_break_addr(&mut self, cmd: &[&str]) -> bool {
        if self.info.brk_addr.is_some() {
            eprintln!("<< break point is already set: Addr = {:p}>>", self.info.brk_addr.unwrap());
            return false;
        } else if let Some(addr) = get_break_addr(cmd) {    // command を parse
            self.info.brk_addr = Some(addr);
            return true;
        } else {
            return false;
        }
    }

    fn do_cmd_common(&self, cmd: &[&str]) {
        match cmd[0] {
            "help" | "h" => do_help(),
            _ => (), 
        }
    }
}

// 特殊化: 特定の型引数に対して method を定義
// NotRunning の時のみ呼び出せる method
impl MyDebug<NotRunning> {
    pub fn new(filename: String) -> Self {
        MyDebug { 
            info: Box::new(DbgInfo { 
                pid: Pid::from_raw(0), 
                brk_addr: None, 
                brk_val: 0, 
                filename 
            }), 
            _state: NotRunning,
        }
    }

    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, DynError> {      // self は消費される
        if cmd.is_empty() {
            return Ok(State::NotRunning(self));
        }

        match cmd[0] {
            "run" | "r" => return self.do_run(cmd),     // プロセス実行、 Running に遷移
            "break" | "b" => {                          // break point 設定、状態は遷移しない
                self.set_break_addr(cmd)
            },       
            "exit" => return Ok(State::Exit),
            "continue" | "c" | "stepi" | "s" | "registers" | "regs" => {
                eprintln!("<<プロセスを実行していません>>");
            }
            _ => self.do_cmd_common(cmd),
        }
        return Ok(State::NotRunning(self));
    }

    // 子プロセス実行、 Running に遷移
    fn do_run(mut self, cmd: &[&str]) -> Result<State, DynError> {
        let args: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
        match unsafe {fork()?} {        // 子プロセス起動
            ForkResult::Child => {
                // ASLR (アドレス空間配置のランダム化) を無効化: デバッグ時は不便なため
                let p = personality::get().unwrap();
                personality::set(p | Persona::ADDR_NO_RANDOMIZE).unwrap();
                ptrace::traceme().unwrap();     // exec するとプロセスが停止するようになる

                // 子プロセスをデバッグ対象のプログラムに置き換え
                execvp(&CString::new(self.info.filename.as_str()).unwrap(), &args).unwrap();
                unreachable!();
            }
            // 子プロセスが停止するのを待つ: traceme() によって、子プロセスは停止 or 終了するはず
            ForkResult::Parent { child, .. } => match waitpid(child, None)? {
                WaitStatus::Stopped(..) => {
                    println!("<< 子プロセスの実行に成功しました: PID = {child} >>");
                    self.info.pid = child;
                    let mut dbg = MyDebug::<Running> {
                        info: self.info,
                        _state: Running,
                    };
                    dbg.set_break()?;
                    dbg.do_continue()
                }
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    Err("子プロセスの実行に失敗しました".into());
                }
                _ => Err("子プロセスが不正な状態です".into()),
            }
        }
    }
}

// Running の時のみ呼び出せる method
impl MyDebug<Running> {
    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, DynError> {
        if cmd.is_empty() {
            return Ok(State::Running(self));
        }

        match cmd[0] {
            "break" | "b" => self.do_break(cmd)?,
            "continue" | "c" => return self.do_continue(),
            "registers" | "regs" => {
                let regs = ptrace::getregs(self.info.pid)?;
                print_regs(&regs);
            }
            "stepi" | "s" => return self.do_stepi(),
            "run" | "r" => eprintln!("<< 既に実行中 >>"),
            "exit" => {
                self.do_exit()?;
                return Ok(State::Exit);
            }
            _ => self.do_cmd_common(cmd),
        }
        Ok(State::Running(self))
    }

    fn print_regs(regs: &user_regs_struct) {
        println!(r#"
            RIP: {:#016x}, RSP: {:#016x}, RBP: {:#016x}
            RAX: {:#016x}, RBX: {:#016x}, RCX: {:#016x}
            RDX: {:#016x}, RSI: {:#016x}, RDI: {:#016x}
            R8 : {:#016x}, R9 : {:#016x}, R10: {:#016x}
            R11: {:#016x}, R12: {:#016x}, R13: {:#016x}
            R14: {:#016x}, R15: {:#016x}"#, 
            regs.rip, regs.rsp, regs.rbp, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi,
            regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15
        );
    }

    fn do_exit(self) -> Result<(), DynError> {
        loop {
            ptrace::kill(self.info.pid)?;   // kill signal が子プロセスに送信される
            match waitpid(self.info.pid, None)? {       // 終了処理
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => return Ok(()),
                _ => (),
            }
        }
    }

    fn do_break(&mut self, cmd: &[&str]) -> Result<(), DynError> {
        if self.set_break_addr(cmd) {
            self.set_break()?;
        }
        Ok(())
    }

    // break point を設定
    fn set_break(&mut self) -> Result<(), DynError> {
        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(());
        };

        // アドレス addr 上のメモリの値を取得
        let val = match ptrace::read(self.info.pid, addr) {
            Ok(val) => val,
            Err(e) => {
                eprintln!("<< ptrace::read に失敗: {e}, addr = {:p} >>", addr);
                return Ok(());
            }
        };

        // メモリ上の値を表示する subroutine
        fn print_val(addr: usize, val: i64) {
            print!("{:x}:", addr);
            for n in (0..8).map(|n| ((val >> (n * 8)) & 0xff) as u8) {
                print!(" {:x}", n);
            }
        }

        println!("<< 以下のようにメモリを書き換えます >>");
        print!("<< before: ");
        print_val(addr as usize, val);
        println!(" >>");

        let val_int3 = (val & !0xff) | 0xcc;    // int 3 コマンドの bit
        print!("<< after: ");
        print_val(addr as usize, val_int3);
        println!(" >>");

        // int 3 をメモリに書き込む
        match unsafe { ptrace::write(self.info.pid, addr, val_int3 as *mut c_void) } {
            Ok(_) => {
                self.info.brk_addr = Some(addr);
                self.info.brk_val = val;    // 元の値
            }
            Err(e) => {
                eprintln!("<< ptrace::write に失敗: {e}, addr = {:p} >>", addr);
            }
        }
    }

    fn do_continue(self) -> Result<State, DynError> {
        match self.step_and_break()? {  // break point で停止していた場合は 1 step 実行する
            State::Running(r) => {
                ptrace::cont(r.info.pid, None)?;
                r.wait_child()
            }
            n => Ok(n),
        }
    }

    fn step_and_break(mut self) -> Result<State, DynError> {
        let regs = ptrace::getregs(self.info.pid)?;     // register 取得
        if Some((regs.rip) as *mut c_void) == self.info.brk_addr {      // rip: program counter 
            // program counter が break point ならば
            ptrace::step(self.info.pid, None)?;     // 1 step 実行
            match waitpid(self.info.pid, None)? {       // 停止
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    println!("<< 子プロセスは終了しました >>");
                    return Ok(State::NotRunning(MyDebug::<NotRunning> {
                        info: self.info,
                        _state: NotRunning,
                    }));
                }
                _ => (),
            }
            self.set_break()?;
        }
        Ok(State::Running(self))
    }

    fn wait_child(self) -> Result<State, DynError> {
        match waitpid(self.info.pid, None)? {
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                println!("<< 子プロセスが終了しました >>");
                let not_run = MyDebug::<NotRunning> {
                    info: self.info,
                    _state: NotRunning,
                };
                Ok(State::NotRunning(not_run))
            }
            WaitStatus::Stopped(..) => {
                let mut regs = ptrace::getregs(self.info.pid)?;
                if Some((regs.rip - 1) as *mut c_void) == self.info.brk_addr {      // break point で停止した場合
                    unsafe {        // 書き換えたメモリを元に戻す
                        ptrace::write(self.info.pid, self.info.brk_addr.unwrap(), self.info.brk_val as *mut c_void)?
                    };
                
                    regs.rip -= 1;
                    ptrace::setregs(self.info.pid, regs)?;
                }
                println!("<< 子プロセスが停止しました : PC = {:#x} >>", regs.rip);

                Ok(State::Running(self))
            }
            _ => Err("invalid waitpid() value".into()),
        }
    }

    // 機械語レベルで一行実行
    fn do_stepi(self) -> Result<State, DynError> {
        let regs = ptrace::getregs(self.info.pid)?;
        if Some((regs.rip) as *mut c_void) == self.info.brk_addr {  // 次の実行先が break point
            unsafe {    // 0xcc に書き換えたメモリを元に戻してから実行
                ptrace::write(self.info.pid, self.info.brk_addr.unwrap(), self.info.brk_val as *mut c_void)?
            };
            self.step_and_break()
        } else {
            ptrace::step(self.info.pid, None)?;
            self.wait_child()
        }
    }
}

fn do_help() {
    println!(r#"
        コマンド一覧 (省略表記)
        break 0x8000    : ブレークポイントを 0x8000 番地に設定 (b 0x8000)
        run             : プログラムを実行 (r)
        continue        : プログラムを再開 (c) 
        stepi           : 機械語レベルで 1 step 実行 (s)
        registers       : レジスタを表示 (regs)
        exit            : 終了
        help            : このヘルプを表示 (h)
    "#);
}

fn get_break_addr(cmd: &[&str]) -> Option<*mut c_void> {
    if cmd.len() < 2 {
        eprintln!("<< アドレスを指定してください\n ex: break 0xZZZZ >>");
        return None;
    }

    let addr_str = cmd[1];
    if &addr_str[0..2] != "0x" {
        eprintln!("<< アドレスは 16 進数です >>");
        return None;
    }

    let addr = match usize::from_str_radix(&addr_str[2..], 16) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("<< invalid address: {e} >>");
            return None;
        }
    } as *mut c_void;

    Some(addr)
}