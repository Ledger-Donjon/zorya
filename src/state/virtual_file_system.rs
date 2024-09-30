use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct VirtualFileSystem {
    open_files: HashMap<u32, Arc<Mutex<FileDescriptor>>>,
    file_counter: u32,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        VirtualFileSystem {
            open_files: HashMap::new(),
            file_counter: 0,
        }
    }

    /// Opens a file and returns a file descriptor.
    pub fn open(&mut self, _filename: &str) -> u32 {
        let fd = self.file_counter;
        self.file_counter += 1;
        // Mock behavior for opening a file with a size, e.g., 1024 bytes
        self.open_files.insert(fd, Arc::new(Mutex::new(FileDescriptor::new(fd, 1024))));
        fd
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
    fd: u32,
    position: u64, // Current position in the file
    size: u64,     // Size of the file
}

impl FileDescriptor {
    fn new(fd: u32, size: u64) -> Self {
        FileDescriptor { fd, position: 0, size }
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
            },
            SeekFrom::Current(offset) => {
                if offset < 0 {
                    self.position.saturating_sub((-offset) as u64)
                } else {
                    self.position.checked_add(offset as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::Other, "Seek position overflow")
                    })?
                }
            },
        };
        Ok(self.position)
    }
}
