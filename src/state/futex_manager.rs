// FutexManager is a simple implementation of the futex system call
// It is used to implement the futex system call in the kernel

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, Condvar};
use std::time::Duration;

struct Futex {
    count: i32,
    waiters: usize,
    condvar: Condvar,
}

pub struct FutexManager {
    futexes: Mutex<BTreeMap<u64, Arc<Mutex<Futex>>>>,
}

impl FutexManager {
    pub fn new() -> Self {
        FutexManager {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn futex_wait(&self, uaddr: u64, val: i32, timeout: Option<Duration>) -> Result<(), String> {
        let mut futexes = self.futexes.lock().unwrap();
        let futex = futexes.entry(uaddr).or_insert_with(|| Arc::new(Mutex::new(Futex { count: val, waiters: 0, condvar: Condvar::new() }))).clone();

        let mut futex_guard = futex.lock().unwrap();
        if futex_guard.count != val {
            return Err("EWOULDBLOCK".to_string());
        }

        futex_guard.waiters += 1;

        let result = if let Some(to) = timeout {
            let condvar = &futex_guard.condvar;
            let futex = Arc::clone(&futex);
            let mut futex_guard = futex.lock().unwrap();
            let (guard, timeout_result) = condvar.wait_timeout_while(futex_guard, to, |futex| futex.count == val).unwrap();
            futex_guard = guard;
            if timeout_result.timed_out() {
                Err("ETIMEDOUT".to_string())
            } else {
                Ok(())
            }
        } else {
            let condvar = &futex_guard.condvar;
            let futex = Arc::clone(&futex);
            let mut futex_guard = futex.lock().unwrap();
            futex_guard = condvar.wait_while(futex_guard, |futex| futex.count == val).unwrap();
            Ok(())
        };

        futex_guard.waiters -= 1;
        result
    }

    pub fn futex_wake(&self, uaddr: u64, val: usize) -> Result<usize, String> {
        let futexes = self.futexes.lock().unwrap();
        if let Some(futex) = futexes.get(&uaddr) {
            let mut futex_guard = futex.lock().unwrap();
            let to_wake = std::cmp::min(val, futex_guard.waiters);
            for _ in 0..to_wake {
                futex_guard.condvar.notify_one();
            }
            futex_guard.waiters -= to_wake;
            Ok(to_wake)
        } else {
            Ok(0)
        }
    } 

    pub fn futex_requeue(&self, uaddr: u64, nwake: usize, requeue_uaddr: u64, nrequeue: usize) -> Result<usize, String> {
        let mut futexes = self.futexes.lock().unwrap();
        let futex = futexes.get(&uaddr).cloned();
        let requeue_futex = futexes.entry(requeue_uaddr).or_insert_with(|| Arc::new(Mutex::new(Futex { count: 0, waiters: 0, condvar: Condvar::new() }))).clone();

        if let Some(futex) = futex {
            let mut futex_guard = futex.lock().unwrap();
            let to_wake = std::cmp::min(nwake, futex_guard.waiters);
            for _ in 0..to_wake {
                futex_guard.condvar.notify_one();
            }

            let mut requeue_futex_guard = requeue_futex.lock().unwrap();
            let to_requeue = std::cmp::min(nrequeue, futex_guard.waiters - to_wake);
            requeue_futex_guard.waiters += to_requeue;
            futex_guard.waiters -= to_requeue;

            Ok(to_wake)
        } else {
            Ok(0)
        }
    }
}

impl fmt::Debug for FutexManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FutexManager with active futexes")
    }
}

impl Clone for FutexManager {
    fn clone(&self) -> Self {
        let futexes = self.futexes.lock().unwrap();
        let cloned_futexes = futexes.iter().map(|(uaddr, futex)| (*uaddr, Arc::clone(futex))).collect();
        FutexManager {
            futexes: Mutex::new(cloned_futexes),
        }
    }
}