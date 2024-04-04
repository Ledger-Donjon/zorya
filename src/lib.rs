pub mod concolic;
pub mod state;
pub mod target_info;

pub use concolic::{concolic_var, executor};

#[macro_use]
extern crate lazy_static;