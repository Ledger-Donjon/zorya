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

    // Creates a new file within the file system at a specified path with given data.
    pub fn create_file(&self, path: String, data: Vec<u8>) -> Result<Rc<RefCell<FileObject>>, String> {
        let (dir_path, file_name) = self.parse_path(&path)?;
        let directory = self.get_or_create_directory(&dir_path)?;
        
        // Ensure the file does not already exist in the directory.
        if directory.borrow().children.contains_key(&file_name) {
            return Err("File already exists".to_string());
        }

        let file = Rc::new(RefCell::new(FileObject {
            name: file_name.clone(),
            data,
        }));
        directory.borrow_mut().children.insert(file_name, FileSystemNode::File(file.clone()));
        Ok(file)
    }

    // Parses a file system path into directory path and file name components.
    fn parse_path(&self, path: &str) -> Result<(String, String), String> {
        let parts: Vec<&str> = path.rsplitn(2, '/').collect();
        let file_name = parts[0].to_string();
        let dir_path = parts.get(1).unwrap_or(&"").to_string();
        Ok((dir_path, file_name))
    }

    // Finds an existing directory or creates a new one if it doesn't exist.
    fn get_or_create_directory(&self, path: &str) -> Result<Rc<RefCell<DirectoryObject>>, String> {
        let parts = path.split('/').filter(|p| !p.is_empty());
        let mut current_dir = Rc::clone(&self.root);
        for part in parts {
            let temp_dir = {
                let mut current_dir_borrow = current_dir.borrow_mut();
                current_dir_borrow.children.entry(part.to_string()).or_insert_with(|| {
                    FileSystemNode::Directory(Rc::new(RefCell::new(DirectoryObject {
                        name: part.to_string(),
                        children: HashMap::new(),
                    })))
                });
                match current_dir_borrow.children.get(part).unwrap() {
                    FileSystemNode::Directory(dir) => Rc::clone(dir),
                    _ => return Err("Path component is not a directory".to_string()),
                }
            };
            current_dir = temp_dir;
        }
        Ok(current_dir)
    }

    // Helper function to find or create a directory given a path.
    pub fn find_or_create_directory(&self, path: &str) -> Result<bool, String> {
        let mut root = self.root.borrow_mut();
        if root.children.contains_key(path) {
            Ok(false) // Directory already exists
        } else {
            let directory = Rc::new(RefCell::new(DirectoryObject {
                name: path.to_string(),
                children: HashMap::new(),
            }));
            root.children.insert(path.to_string(), FileSystemNode::Directory(Rc::clone(&directory)));
            Ok(true) // Directory was created
        }
    }

    // Copy a file
    pub fn copy_file(&self, source_path: &str, destination_path: &str) -> Result<(), String> {
        // Temporarily drop borrow by scoping the file_data extraction
        let file_data = {
            let root = self.root.borrow();
            if let Some(FileSystemNode::File(file)) = root.children.get(source_path) {
                Some(file.borrow().data.clone())
            } else {
                None
            }
        };

        // Proceed with the operation based on the extracted data
        match file_data {
            Some(data) => self.create_file(destination_path.to_string(), data).map(|_| ()),
            None => Err("Source file not found".to_string()),
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

    // Function to write data to a file at the current position and returns the number of bytes written
    pub fn write(&self, fd: &mut FileDescriptor, data: &[u8]) -> Result<usize, String> {
        let mut file = fd.file.borrow_mut();
        let before_len = file.data.len();
        file.data.splice(fd.position..fd.position, data.iter().cloned());
        fd.position += data.len();
        let after_len = file.data.len();
        let bytes_written = after_len - before_len;
        Ok(bytes_written)
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
        // Create a directory explicitly
        assert!(vfs.find_or_create_directory("directory").is_ok());
        // Create a file within the directory
        assert!(vfs.create_file("directory/file1.txt".to_string(), vec![1, 2, 3]).is_ok());
        // List the contents of the directory
        let contents = vfs.list_directory("directory").unwrap();
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