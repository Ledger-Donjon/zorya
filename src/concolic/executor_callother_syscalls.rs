/// Focuses on implementing the execution of the CALLOTHER opcode from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use nix::libc::{SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::ast::BV;
use std::{io::Write, process, time::{Duration, SystemTime, UNIX_EPOCH}};

use super::{ConcolicEnum, ConcolicVar, SymbolicVar};

// constants for sys_futex operations
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 2;
const FUTEX_WAKE_PRIVATE: u64 = 129;
// constants for sys_sigaltstack
const SS_DISABLE: u32 = 1;
const MINSIGSTKSZ: usize = 2048;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}
