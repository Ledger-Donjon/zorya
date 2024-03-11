use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;

// Define a filesystem node that can either be a file or a directory.
#[derive(Debug, Clone)]
pub enum FileSystemNode {
    File(Rc<RefCell<FileObject>>),
    Directory(Rc<RefCell<DirectoryObject>>),
}

// Define the structure of a file object with a name and data.
#[allow(dead_code)]
#[derive(Debug)]
pub struct FileObject {
    name: String,
    data: Vec<u8>,
}

// Define the structure of a directory object with a name and children.
// Children can be either files or directories, enabling a hierarchical structure.
#[allow(dead_code)]
#[derive(Debug)]
pub struct DirectoryObject {
    name: String,
    children: HashMap<String, FileSystemNode>,
}

// Define a file descriptor that includes a reference to the file object and a current position within the file.
#[derive(Debug)]
pub struct FileDescriptor {
    file: Rc<RefCell<FileObject>>,
    position: usize,
}

impl FileDescriptor {
    // Constructor for creating a new FileDescriptor pointing to a file object.
    fn new(file: Rc<RefCell<FileObject>>) -> Self {
        FileDescriptor { file, position: 0 }
    }
}

// The virtual file system itself, starting with a root directory.
#[derive(Debug)]
pub struct VirtualFileSystem {
    root: Rc<RefCell<DirectoryObject>>,
}

impl VirtualFileSystem {
    // Constructor for creating a new VirtualFileSystem with an empty root directory.
    pub fn new() -> Self {
        let root = Rc::new(RefCell::new(DirectoryObject {
            name: "/".to_string(),
            children: HashMap::new(),
        }));
        VirtualFileSystem { root }
    }

    // Function to create a file within the file system.
    pub fn create_file(&self, path: String, data: Vec<u8>) -> Result<Rc<RefCell<FileObject>>, String> {
        let mut root = self.root.borrow_mut();
        if root.children.contains_key(&path) {
            return Err("File already exists".to_string());
        }
        let file = Rc::new(RefCell::new(FileObject {
            name: path.clone(),
            data,
        }));
        root.children.insert(path, FileSystemNode::File(Rc::clone(&file)));
        Ok(file)
    }

    // Copy a file
    pub fn copy_file(&self, source_path: &str, destination_path: &str) -> Result<(), String> {
        let root = self.root.borrow();
        if let Some(FileSystemNode::File(file)) = root.children.get(source_path) {
            let file_data = file.borrow().data.clone();
            self.create_file(destination_path.to_string(), file_data)?;
            Ok(())
        } else {
            Err("Source file not found".to_string())
        }
    }    

    // List the contents of a directory
    pub fn list_directory(&self, path: &str) -> Result<Vec<String>, String> {
        let root = self.root.borrow();
        if let Some(FileSystemNode::Directory(directory)) = root.children.get(path) {
            let directory = directory.borrow();
            Ok(directory.children.keys().cloned().collect())
        } else {
            Err("Directory not found".to_string())
        }
    }

    // Function to open a file, returning a FileDescriptor if successful.
    pub fn open(&self, path: &str) -> Result<FileDescriptor, String> {
        let root = self.root.borrow();
        root.children.get(path).and_then(|node| match node {
            FileSystemNode::File(file) => Some(FileDescriptor::new(Rc::clone(file))),
            _ => None,
        }).ok_or_else(|| "File not found".to_string())
    }

    // Function to read data from a file into a buffer.
    pub fn read(&self, fd: &FileDescriptor, buffer: &mut Vec<u8>, size: usize) -> Result<(), String> {
        let file = fd.file.borrow();
        let start = fd.position;
        let end = std::cmp::min(file.data.len(), start + size);
        buffer.clear();
        buffer.extend_from_slice(&file.data[start..end]);
        Ok(())
    }

    // Function to write data to a file at the current position.
    pub fn write(&self, fd: &mut FileDescriptor, data: &[u8]) -> Result<(), String> {
        let mut file = fd.file.borrow_mut();
        file.data.splice(fd.position..fd.position, data.iter().cloned());
        fd.position += data.len();
        Ok(())
    }

    // Function to delete a file or directory from the filesystem.
    pub fn delete(&self, path: &str) -> Result<(), String> {
        let mut root = self.root.borrow_mut();
        if root.children.remove(path).is_some() {
            Ok(())
        } else {
            Err("File not found".to_string())
        }
    }

    // Function to seek to a new position within a file.
    pub fn seek(&mut self, fd: &mut FileDescriptor, position: usize) -> Result<(), String> {
        let file = fd.file.borrow();
        if position <= file.data.len() {
            fd.position = position;
            Ok(())
        } else {
            Err("Position out of bounds".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_list_directory() {
        let vfs = VirtualFileSystem::new();
        vfs.create_file("file1.txt".to_string(), vec![1, 2, 3]).unwrap();
        let contents = vfs.list_directory("/").unwrap();
        assert_eq!(contents, vec!["file1.txt"]);
    }

    #[test]
    fn test_open_and_read_file() {
        let vfs = VirtualFileSystem::new();
        vfs.create_file("readme.txt".to_string(), b"Hello, world!".to_vec()).unwrap();
        let fd = vfs.open("readme.txt").unwrap();
        let mut buffer = vec![];
        vfs.read(&fd, &mut buffer, 13).unwrap();
        assert_eq!(buffer, b"Hello, world!");
    }

    #[test]
    fn test_write_and_seek_file() {
        let mut vfs = VirtualFileSystem::new();
        let fd = vfs.create_file("log.txt".to_string(), vec![]).unwrap();
        vfs.write(&mut FileDescriptor::new(fd), b"Hello".as_ref()).unwrap();
        let mut fd = vfs.open("log.txt").unwrap();
        vfs.seek(&mut fd, 5).unwrap();
        vfs.write(&mut fd, b", world!".as_ref()).unwrap();
        let mut buffer = vec![];
        let fd = vfs.open("log.txt").unwrap();
        vfs.read(&fd, &mut buffer, 13).unwrap();
        assert_eq!(buffer, b"Hello, world!");
    }

    #[test]
    fn test_delete_file() {
        let vfs = VirtualFileSystem::new();
        vfs.create_file("delete_me.txt".to_string(), vec![1, 2, 3]).unwrap();
        assert!(vfs.delete("delete_me.txt").is_ok());
        assert!(vfs.open("delete_me.txt").is_err());
    }

    #[test]
    fn test_copy_file() {
        let vfs = VirtualFileSystem::new();
        vfs.create_file("original.txt".to_string(), b"Content".to_vec()).unwrap();
        vfs.copy_file("original.txt", "copy.txt").unwrap();
        let fd = vfs.open("copy.txt").unwrap();
        let mut buffer = vec![];
        vfs.read(&fd, &mut buffer, 7).unwrap();
        assert_eq!(buffer, b"Content");
    }

}