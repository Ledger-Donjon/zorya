use std::collections::HashMap;

// Define a simple virtual filesystem
#[derive(Debug, Clone)]
pub struct VirtualFileSystem {
    open_files: HashMap<u32, FileDescriptor>,
    file_counter: u32,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        VirtualFileSystem {
            open_files: HashMap::new(),
            file_counter: 0,
        }
    }

    pub fn open(&mut self, _filename: &str) -> u32 {
        let fd = self.file_counter;
        self.file_counter += 1;
        // Mock behavior for opening a file
        self.open_files.insert(fd, FileDescriptor::new(fd));
        fd
    }

    pub fn read(&self, fd: u32, buffer: &mut [u8]) -> usize {
        // Mock behavior for reading a file
        let len = buffer.len();
        buffer.fill(b'x');
        len
    }

    pub fn write(&self, fd: u32, data: &[u8]) -> usize {
        // Mock behavior for writing to a file
        data.len()
    }

    pub fn close(&mut self, fd: u32) {
        self.open_files.remove(&fd);
    }
}

#[derive(Debug, Clone)]
struct FileDescriptor {
    fd: u32,
}

impl FileDescriptor {
    fn new(fd: u32) -> Self {
        FileDescriptor { fd }
    }
}