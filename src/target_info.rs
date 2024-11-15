/// File containing all the information regarding the binary file to be analyzed by zorya

use std::{env, path::PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub binary_path: String,
    pub main_program_addr: String,
    pub pcode_file_path: PathBuf,
    pub zorya_path: PathBuf,
}

impl TargetInfo {
    // Define a new function for easily creating a new TargetInfo
    pub fn new(binary_path: &str, main_program_addr: &str, pcode_file_path: PathBuf, zorya_path: PathBuf) -> Self {
        TargetInfo {
            binary_path: binary_path.to_string(),
            main_program_addr: main_program_addr.to_string(),
            pcode_file_path,
            zorya_path,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_TARGET_INFO: Mutex<TargetInfo> = Mutex::new({
        // Get ZORYA_DIR and BIN_PATH from environment
        let zorya_path = PathBuf::from(env::var("ZORYA_DIR").expect("ZORYA_DIR environment variable is not set"));
        let bin_path = PathBuf::from(env::var("BIN_PATH").expect("BIN_PATH environment variable is not set"));
        
        // Extract binary name from BIN_PATH and construct the pcode file path
        let binary_name = bin_path.file_name()
            .expect("Failed to extract binary name from BIN_PATH")
            .to_str()
            .expect("Binary name contains invalid UTF-8 characters");
        
        let pcode_file_name = format!("{}_low_pcode.txt", binary_name);
        let pcode_file_path = zorya_path.join("external/pcode-generator/results").join(pcode_file_name);

        TargetInfo::new(
            &bin_path.to_string_lossy().to_string(),
            &env::var("START_POINT").expect("START_POINT environment variable is not set"),
            pcode_file_path,
            zorya_path,
        )
    });
}

// From pcode-generator/tests :
// additiongo - addr of main.main func : 0x4585c0
// calculus - addr of main.main func : 0x48fca0
