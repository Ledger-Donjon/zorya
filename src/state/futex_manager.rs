// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

// FutexManager is a simple implementation of the futex system call
// It is used to implement the futex system call in the kernel

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct Futex {
    count: i32,
    waiters: usize,
    condvar: Condvar,
}

pub struct FutexManager {
    futexes: Mutex<BTreeMap<u64, Arc<Mutex<Futex>>>>,
}

impl Default for FutexManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexManager {
    pub fn new() -> Self {
        FutexManager {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn futex_wait(
        &self,
        uaddr: u64,
        val: i32,
        timeout: Option<Duration>,
    ) -> Result<(), String> {
        let mut futexes = self.futexes.lock().unwrap();
        let futex = futexes
            .entry(uaddr)
            .or_insert_with(|| {
                Arc::new(Mutex::new(Futex {
                    count: val,
                    waiters: 0,
                    condvar: Condvar::new(),
                }))
            })
            .clone();

        // Drop the futexes lock to avoid holding it during wait
        drop(futexes);

        let mut futex_guard = futex.lock().unwrap();
        if futex_guard.count != val {
            return Err("EWOULDBLOCK".to_string());
        }

        futex_guard.waiters += 1;

        // The key insight: we need to temporarily take ownership of the condvar
        // to avoid the borrow checker issues
        let condvar = std::mem::replace(&mut futex_guard.condvar, Condvar::new());

        let (mut final_guard, result) = if let Some(to) = timeout {
            // For timeout case
            match condvar.wait_timeout_while(futex_guard, to, |futex| futex.count == val) {
                Ok((new_guard, timeout_result)) => {
                    let result = if timeout_result.timed_out() {
                        Err("ETIMEDOUT".to_string())
                    } else {
                        Ok(())
                    };
                    (new_guard, result)
                }
                Err(_) => {
                    // If wait fails, we need to get the guard back somehow
                    // This is tricky - let's re-acquire the lock
                    let guard = futex.lock().unwrap();
                    (guard, Err("WAIT_ERROR".to_string()))
                }
            }
        } else {
            // For no timeout case
            match condvar.wait_while(futex_guard, |futex| futex.count == val) {
                Ok(new_guard) => (new_guard, Ok(())),
                Err(_) => {
                    // If wait fails, re-acquire the lock
                    let guard = futex.lock().unwrap();
                    (guard, Err("WAIT_ERROR".to_string()))
                }
            }
        };

        // Restore the condvar back to the futex
        final_guard.condvar = condvar;
        final_guard.waiters -= 1;
        result
    }

    pub fn futex_wake(&self, uaddr: u64, nr_wake: i32) -> Result<i32, String> {
        let futexes = self.futexes.lock().unwrap();

        if let Some(futex) = futexes.get(&uaddr) {
            let futex_guard = futex.lock().unwrap();
            let woken = std::cmp::min(nr_wake, futex_guard.waiters as i32);

            // Notify the appropriate number of waiters
            for _ in 0..woken {
                futex_guard.condvar.notify_one();
            }

            Ok(woken)
        } else {
            // No futex at this address, so no waiters to wake
            Ok(0)
        }
    }

    pub fn futex_wake_all(&self, uaddr: u64) -> Result<i32, String> {
        let futexes = self.futexes.lock().unwrap();

        if let Some(futex) = futexes.get(&uaddr) {
            let futex_guard = futex.lock().unwrap();
            let woken = futex_guard.waiters as i32;

            // Notify all waiters
            futex_guard.condvar.notify_all();

            Ok(woken)
        } else {
            // No futex at this address, so no waiters to wake
            Ok(0)
        }
    }

    pub fn futex_requeue(
        &self,
        uaddr: u64,
        nwake: usize,
        requeue_uaddr: u64,
        nrequeue: usize,
    ) -> Result<usize, String> {
        let mut futexes = self.futexes.lock().unwrap();
        let futex = futexes.get(&uaddr).cloned();
        let requeue_futex = futexes
            .entry(requeue_uaddr)
            .or_insert_with(|| {
                Arc::new(Mutex::new(Futex {
                    count: 0,
                    waiters: 0,
                    condvar: Condvar::new(),
                }))
            })
            .clone();

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
        let cloned_futexes = futexes
            .iter()
            .map(|(uaddr, futex)| (*uaddr, Arc::clone(futex)))
            .collect();
        FutexManager {
            futexes: Mutex::new(cloned_futexes),
        }
    }
}
