pub mod concolic;
pub mod state;

pub use concolic::{concolic_var, executor};

#[macro_use]
extern crate lazy_static;