use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Argument {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,

    // Either a single register name, or multiple (e.g., strings/slices), or a stack location
    #[serde(default)]
    pub register: Option<String>,
    #[serde(default)]
    pub registers: Option<Vec<String>>,
    #[serde(default)]
    pub location: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FunctionSignature {
    pub address: String,
    pub name: String,
    pub arguments: Vec<Argument>,
}

#[derive(Deserialize)]
pub struct FunctionSigWrapper {
    pub functions: Vec<FunctionSignature>
}
