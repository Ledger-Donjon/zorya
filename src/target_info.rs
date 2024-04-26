/// File containing all the information regarding the binary file to be analyzed by zorya

use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub binary_path: String,
    pub main_program_addr: String,
    pub pcode_file_path: PathBuf,
    pub working_files_dir: PathBuf,
    pub memory_dumps: PathBuf,
}

impl TargetInfo {
    // Define a new function for easily creating a new TargetInfo
    pub fn new(binary_path: &str, main_program_addr: &str, pcode_file_path: PathBuf, working_files_dir: PathBuf, memory_dumps: PathBuf) -> Self {
        TargetInfo {
            binary_path: binary_path.to_string(),
            main_program_addr: main_program_addr.to_string(),
            pcode_file_path,
            working_files_dir,
            memory_dumps,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_TARGET_INFO: Mutex<TargetInfo> = Mutex::new(TargetInfo::new(
        // *********************************
        // MODIFY INFO HERE
        // 1. Path to target binary
        "/home/kgorna/Documents/tools/pcode-generator/tests/additiongo/additiongo",
        // 2. Address of the main or main.main function in your binary (check Ghidra or readelf)
        "0x4585c0",
        // 3. Absolute path to the .txt file with the pcode commands of your binary generated with Pcode-generator
        PathBuf::from("/home/kgorna/Documents/tools/pcode-generator/results/additiongo_low_pcode.txt"),
        // 4. Absolute path to the /src/state/working_files dir
        PathBuf::from("/home/kgorna/Documents/zorya/src/state/working_files"),
        // 5. Absolute path to the memory dumps from qemu-mount dir
        PathBuf::from("/home/kgorna/Documents/zorya/external/qemu-mount/dumps"),
        // *********************************
    ));
}

// From pcode-generator/tests :
// additiongo - addr of main.main func : 0x4585c0
// calculus - addr of main.main func : 0x48fca0
