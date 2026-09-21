//! Fail-closed Lithic-to-native-LithoVM backend.
//!
//! Version 1 deliberately starts with the same stateless static-value subset
//! used to establish the compiler/runtime boundary. Unsupported declarations
//! reject the whole compilation; no source behavior is silently discarded.

use lithic_syntax::{Contract, Item, Type};
use lithovm_bytecode::{Function, Program, ReturnValue, ValueType, VERSION};
use serde::Serialize;
use std::fmt;

pub const TARGET: &str = "lithovm-native-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub contract_name: String,
    pub target: String,
    pub bytecode_version: u8,
    pub abi: serde_json::Value,
    pub bytecode: String,
}

impl Artifact {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("artifact serialization cannot fail")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    messages: Vec<String>,
}

impl CompileError {
    fn one(message: impl Into<String>) -> Self {
        Self {
            messages: vec![message.into()],
        }
    }

    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.messages.join("\n"))
    }
}

impl std::error::Error for CompileError {}

pub fn compile(source: &str) -> Result<Artifact, CompileError> {
    let parsed = lithic_syntax::parse(source);
    let mut errors: Vec<String> = parsed
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.is_error())
        .map(|diagnostic| format!("syntax error: {}", diagnostic.message))
        .collect();
    let contract = parsed
        .contract
        .ok_or_else(|| CompileError::one("no contract found"))?;
    errors.extend(
        lithic_syntax::check(&contract)
            .into_iter()
            .filter(|finding| matches!(finding.level, lithic_syntax::Level::Error))
            .map(|finding| format!("declaration error: {}", finding.message)),
    );
    if !errors.is_empty() {
        return Err(CompileError { messages: errors });
    }
    compile_contract(&contract)
}

fn compile_contract(contract: &Contract) -> Result<Artifact, CompileError> {
    let mut errors = Vec::new();
    let mut functions = Vec::new();
    let mut abi = Vec::new();

    for item in &contract.items {
        match item {
            Item::State(state) if !state.fields.is_empty() => errors
                .push("state fields are not supported by native LithoVM bytecode v1".to_string()),
            Item::Const(_) => errors.push(
                "contract constants are not supported by native LithoVM bytecode v1".to_string(),
            ),
            Item::Event(_) => errors.push(
                "event declarations are not supported by native LithoVM bytecode v1".to_string(),
            ),
            Item::Func(function) => match compile_function(function) {
                Ok((compiled, entry)) => {
                    functions.push(compiled);
                    abi.push(entry);
                }
                Err(message) => errors.push(format!("function '{}': {message}", function.name)),
            },
            Item::State(_) => {}
        }
    }
    if functions.is_empty() {
        errors.push("at least one supported public function is required".to_string());
    }
    if !errors.is_empty() {
        return Err(CompileError { messages: errors });
    }

    let program = Program { functions };
    let bytes = program
        .encode()
        .map_err(|error| CompileError::one(format!("bytecode encoding failed: {error}")))?;
    Ok(Artifact {
        contract_name: contract.name.clone(),
        target: TARGET.to_string(),
        bytecode_version: VERSION,
        abi: serde_json::Value::Array(abi),
        bytecode: format!("0x{}", hex::encode(bytes)),
    })
}

fn compile_function(
    function: &lithic_syntax::FuncDecl,
) -> Result<(Function, serde_json::Value), String> {
    if !function.is_pub {
        return Err("private functions are unsupported".to_string());
    }
    if function.is_async {
        return Err("async functions are unsupported".to_string());
    }
    if !function.attrs.is_empty() {
        return Err("function attributes are unsupported".to_string());
    }
    let return_type = lower_type(
        function
            .ret
            .as_ref()
            .ok_or_else(|| "a return type is required".to_string())?,
    )?;
    let parameters = function
        .params
        .iter()
        .map(|parameter| lower_type(&parameter.ty))
        .collect::<Result<Vec<_>, _>>()?;
    let return_value = parse_return(function, return_type, &parameters)?;
    let abi = serde_json::json!({
        "type": "function",
        "name": function.name,
        "inputs": function.params.iter().zip(&parameters).map(|(parameter, value_type)| {
            serde_json::json!({"name": parameter.name, "type": value_type.name()})
        }).collect::<Vec<_>>(),
        "outputs": [{"type": return_type.name()}]
    });
    Ok((
        Function {
            name: function.name.clone(),
            parameters,
            return_type,
            return_value,
        },
        abi,
    ))
}

fn lower_type(value: &Type) -> Result<ValueType, String> {
    match value {
        Type::Named(name) => match name.as_str() {
            "u64" => Ok(ValueType::U64),
            "u256" => Ok(ValueType::U256),
            "bool" => Ok(ValueType::Bool),
            "address" => Ok(ValueType::Address),
            "bytes32" => Ok(ValueType::Bytes32),
            other => Err(format!("type '{other}' has no native LithoVM v1 lowering")),
        },
        Type::Map(_, _) | Type::Vec(_) => Err("collection types are unsupported".to_string()),
    }
}

fn parse_return(
    function: &lithic_syntax::FuncDecl,
    return_type: ValueType,
    parameter_types: &[ValueType],
) -> Result<ReturnValue, String> {
    let body = function.body_src.trim();
    let value = body
        .strip_prefix("return")
        .and_then(|rest| rest.trim().strip_suffix(';'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "expected exactly 'return <constant-or-parameter>;'".to_string())?;

    if let Some((index, _)) = function
        .params
        .iter()
        .enumerate()
        .find(|(_, parameter)| parameter.name == value)
    {
        if parameter_types[index] != return_type {
            return Err(format!(
                "return parameter '{}' has type {}, expected {}",
                value,
                parameter_types[index].name(),
                return_type.name()
            ));
        }
        return Ok(ReturnValue::Parameter(index as u16));
    }
    if value.contains(char::is_whitespace) {
        return Err("constant return expression contains unsupported tokens".to_string());
    }
    Ok(ReturnValue::Constant(parse_constant(value, return_type)?))
}

fn parse_constant(value: &str, value_type: ValueType) -> Result<[u8; 32], String> {
    match value_type {
        ValueType::Bool => match value {
            "true" => Ok(word_from_u64(1)),
            "false" => Ok([0; 32]),
            _ => Err("bool return must be true or false".to_string()),
        },
        ValueType::Address => parse_fixed_hex(value, 20),
        ValueType::Bytes32 => parse_fixed_hex(value, 32),
        ValueType::U64 => value
            .parse::<u64>()
            .map(word_from_u64)
            .map_err(|_| "u64 return must be an unsigned decimal literal".to_string()),
        ValueType::U256 => parse_u256_decimal(value),
    }
}

fn parse_fixed_hex(value: &str, width: usize) -> Result<[u8; 32], String> {
    let encoded = value
        .strip_prefix("0x")
        .ok_or_else(|| "hex constant must start with 0x".to_string())?;
    if encoded.len() != width * 2 {
        return Err(format!("hex constant must contain exactly {width} bytes"));
    }
    let decoded = hex::decode(encoded).map_err(|_| "invalid hex constant".to_string())?;
    let mut word = [0u8; 32];
    word[32 - width..].copy_from_slice(&decoded);
    Ok(word)
}

fn parse_u256_decimal(value: &str) -> Result<[u8; 32], String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("u256 return must be an unsigned decimal literal".to_string());
    }
    let mut word = [0u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        let mut carry = digit as u16;
        for byte in word.iter_mut().rev() {
            let next = (*byte as u16) * 10 + carry;
            *byte = next as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err("u256 literal exceeds 256 bits".to_string());
        }
    }
    Ok(word)
}

fn word_from_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use lithovm::{Vm, BASE_CALL_GAS, PARAMETER_GAS};

    #[test]
    fn compiler_and_native_runtime_execute_the_same_artifact() {
        let artifact = compile(
            "contract C { pub fn answer() -> u64 { return 42; } pub fn echo(value: u64) -> u64 { return value; } }",
        )
        .unwrap();
        assert_eq!(artifact.target, TARGET);
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let vm = Vm::default();
        assert_eq!(
            &vm.execute(&bytes, "answer", &[], BASE_CALL_GAS)
                .unwrap()
                .return_value[24..],
            &42u64.to_be_bytes()
        );
        assert_eq!(
            vm.execute(
                &bytes,
                "echo",
                &[word_from_u64(9005)],
                BASE_CALL_GAS + PARAMETER_GAS,
            )
            .unwrap()
            .return_value,
            word_from_u64(9005)
        );
    }

    #[test]
    fn output_is_deterministic_and_fail_closed() {
        let source = "contract C { pub fn answer() -> u64 { return 42; } }";
        assert_eq!(compile(source).unwrap(), compile(source).unwrap());
        for unsupported in [
            "contract C { state { value: u64; } pub fn x() -> u64 { return 1; } }",
            "contract C { event Seen { value: u64 } pub fn x() -> u64 { return 1; } }",
            "contract C { pub fn x() -> u64 { return 1 + 2; } }",
            "contract C { pub async fn x() -> u64 { return 1; } }",
        ] {
            assert!(compile(unsupported).is_err(), "compiled {unsupported}");
        }
    }
}
