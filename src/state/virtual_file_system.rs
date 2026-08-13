// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::io::{self, SeekFrom};
use std::sync::{Arc, Mutex};

/// errno returned when a path does not exist (No such file or directory).
pub const ENOENT: i32 = 2;

#[derive(Debug, Clone)]
pub struct VirtualFileSystem {
    open_files: HashMap<u32, Arc<Mutex<FileDescriptor>>>,
    file_counter: u32,
    /// Names of files that were removed via `unlink`. A path in this set no
    /// longer exists in the virtual namespace, so a subsequent `unlink` (or a
    /// use of a stale reference) resolves to ENOENT — this is what lets the
    /// analysis reason about double-unlink / remove-after-remove races.
    removed_paths: HashSet<String>,
    /// Names of files opened during this run, used as the known namespace.
    known_paths: HashSet<String>,
}

impl Default for VirtualFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        VirtualFileSystem {
            open_files: HashMap::new(),
            file_counter: 0,
            removed_paths: HashSet::new(),
            known_paths: HashSet::new(),
        }
    }

    /// Opens a file and returns a file descriptor.
    pub fn open(&mut self, filename: &str) -> u32 {
        // Opening (re)establishes the name in the namespace: clear any prior
        // removal so create-then-remove sequences behave sensibly.
        if !filename.is_empty() {
            self.removed_paths.remove(filename);
            self.known_paths.insert(filename.to_string());
        }
        let fd = self.file_counter;
        self.file_counter += 1;
        // Mock behavior for opening a file with a size, e.g., 1024 bytes
        self.open_files
            .insert(fd, Arc::new(Mutex::new(FileDescriptor::new(fd, 1024))));
        fd
    }

    /// Removes a name from the virtual filesystem namespace.
    ///
    /// Returns `Ok(())` when the name existed and is now removed. Returns
    /// `Err(ENOENT)` when the name was already removed earlier in this run,
    /// modelling a real `unlink` of a non-existent path.
    pub fn unlink(&mut self, filename: &str) -> Result<(), i32> {
        if self.removed_paths.contains(filename) {
            // Already gone — a second removal fails with ENOENT.
            return Err(ENOENT);
        }
        self.known_paths.remove(filename);
        self.removed_paths.insert(filename.to_string());
        Ok(())
    }

    /// Returns true if the path currently exists (has not been unlinked).
    pub fn exists(&self, filename: &str) -> bool {
        !self.removed_paths.contains(filename)
    }

    /// Reads data from a file descriptor into a buffer.
    pub fn read(&self, fd: u32, buffer: &mut [u8]) -> usize {
        if let Some(file_desc) = self.open_files.get(&fd) {
            let mut file = file_desc.lock().unwrap();
            file.read(buffer).unwrap_or(0)
        } else {
            0 // FD not found, return 0 bytes read
        }
    }

    /// Writes data from a buffer to a file descriptor.
    pub fn write(&self, fd: u32, data: &[u8]) -> usize {
        if let Some(file_desc) = self.open_files.get(&fd) {
            let mut file = file_desc.lock().unwrap();
            file.write(data).unwrap_or(0)
        } else {
            0 // FD not found, return 0 bytes written
        }
    }

    /// Closes a file descriptor.
    pub fn close(&mut self, fd: u32) {
        self.open_files.remove(&fd);
    }

    /// Retrieves a file descriptor for internal use.
    pub fn get_file(&self, fd: u32) -> Option<Arc<Mutex<FileDescriptor>>> {
        self.open_files.get(&fd).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct FileDescriptor {
    position: u64, // Current position in the file
    size: u64,     // Size of the file
}

impl FileDescriptor {
    fn new(_fd: u32, size: u64) -> Self {
        FileDescriptor { position: 0, size }
    }

    /// Mock read method.
    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.size {
            return Ok(0); // EOF
        }
        let bytes_to_read = usize::min(buffer.len(), (self.size - self.position) as usize);
        for byte in buffer.iter_mut().take(bytes_to_read) {
            *byte = b'x'; // Or any mock data
        }
        self.position += bytes_to_read as u64;
        Ok(bytes_to_read)
    }

    /// Mock write method.
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let bytes_written = data.len();
        self.position += bytes_written as u64;
        if self.position > self.size {
            self.size = self.position;
        }
        Ok(bytes_written)
    }

    /// Seeks to a position in the file.
    pub fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset < 0 {
                    self.size.saturating_sub((-offset) as u64)
                } else {
                    self.size + (offset as u64)
                }
            }
            SeekFrom::Current(offset) => {
                if offset < 0 {
                    self.position.saturating_sub((-offset) as u64)
                } else {
                    self.position
                        .checked_add(offset as u64)
                        .ok_or_else(|| io::Error::other("Seek position overflow"))?
                }
            }
        };
        Ok(self.position)
    }
}
