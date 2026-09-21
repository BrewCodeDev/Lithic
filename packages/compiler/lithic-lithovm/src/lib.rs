//! Fail-closed Lithic-to-native-LithoVM backend.
//!
//! Version 1 deliberately starts with the same stateless static-value subset
//! used to establish the compiler/runtime boundary. Unsupported declarations
//! reject the whole compilation; no source behavior is silently discarded.

use lithic_syntax::{Contract, Item, Type};
use lithovm_bytecode::{Function, Instruction, Program, ReturnValue, ValueType, VERSION};
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
    if let Ok(constant) = parse_constant(value, return_type) {
        return Ok(ReturnValue::Constant(constant));
    }
    let (instructions, expression_type) = ExpressionParser::new(
        value,
        &function
            .params
            .iter()
            .map(|parameter| parameter.name.as_str())
            .collect::<Vec<_>>(),
        parameter_types,
    )?
    .parse()?;
    if expression_type != return_type {
        return Err(format!(
            "expression has type {}, expected {}",
            expression_type.name(),
            return_type.name()
        ));
    }
    Ok(ReturnValue::Expression(instructions))
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExprToken {
    Ident(String),
    Int(String),
    Bool(bool),
    LParen,
    RParen,
    Plus,
    Minus,
    Star,
    Slash,
    EqEq,
    Lt,
    Eof,
}

struct ExpressionParser<'a> {
    tokens: Vec<ExprToken>,
    position: usize,
    depth: usize,
    parameter_names: &'a [&'a str],
    parameter_types: &'a [ValueType],
}

impl<'a> ExpressionParser<'a> {
    fn new(
        source: &str,
        parameter_names: &'a [&'a str],
        parameter_types: &'a [ValueType],
    ) -> Result<Self, String> {
        Ok(Self {
            tokens: lex_expression(source)?,
            position: 0,
            depth: 0,
            parameter_names,
            parameter_types,
        })
    }

    fn parse(mut self) -> Result<(Vec<Instruction>, ValueType), String> {
        let result = self.parse_equality()?;
        if self.current() != &ExprToken::Eof {
            return Err("unexpected token after return expression".to_string());
        }
        Ok(result)
    }

    fn parse_equality(&mut self) -> Result<(Vec<Instruction>, ValueType), String> {
        let mut left = self.parse_comparison()?;
        while self.eat(&ExprToken::EqEq) {
            let right = self.parse_comparison()?;
            if left.1 != right.1 {
                return Err("equality operands must have the same type".to_string());
            }
            left.0.extend(right.0);
            left.0.push(Instruction::Eq);
            left.1 = ValueType::Bool;
        }
        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<(Vec<Instruction>, ValueType), String> {
        let mut left = self.parse_additive()?;
        while self.eat(&ExprToken::Lt) {
            let right = self.parse_additive()?;
            require_u64_pair(left.1, right.1, "comparison")?;
            left.0.extend(right.0);
            left.0.push(Instruction::LtU64);
            left.1 = ValueType::Bool;
        }
        Ok(left)
    }

    fn parse_additive(&mut self) -> Result<(Vec<Instruction>, ValueType), String> {
        let mut left = self.parse_multiplicative()?;
        loop {
            let instruction = if self.eat(&ExprToken::Plus) {
                Some(Instruction::AddU64)
            } else if self.eat(&ExprToken::Minus) {
                Some(Instruction::SubU64)
            } else {
                None
            };
            let Some(instruction) = instruction else {
                break;
            };
            let right = self.parse_multiplicative()?;
            require_u64_pair(left.1, right.1, "arithmetic")?;
            left.0.extend(right.0);
            left.0.push(instruction);
            left.1 = ValueType::U64;
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> Result<(Vec<Instruction>, ValueType), String> {
        let mut left = self.parse_primary()?;
        loop {
            let instruction = if self.eat(&ExprToken::Star) {
                Some(Instruction::MulU64)
            } else if self.eat(&ExprToken::Slash) {
                Some(Instruction::DivU64)
            } else {
                None
            };
            let Some(instruction) = instruction else {
                break;
            };
            let right = self.parse_primary()?;
            require_u64_pair(left.1, right.1, "arithmetic")?;
            left.0.extend(right.0);
            left.0.push(instruction);
            left.1 = ValueType::U64;
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<(Vec<Instruction>, ValueType), String> {
        match self.bump() {
            ExprToken::Int(value) => {
                let value = value
                    .parse::<u64>()
                    .map_err(|_| "expression integer exceeds u64".to_string())?;
                Ok((
                    vec![Instruction::Constant(ValueType::U64, word_from_u64(value))],
                    ValueType::U64,
                ))
            }
            ExprToken::Bool(value) => Ok((
                vec![Instruction::Constant(
                    ValueType::Bool,
                    word_from_u64(u64::from(value)),
                )],
                ValueType::Bool,
            )),
            ExprToken::Ident(name) => {
                let index = self
                    .parameter_names
                    .iter()
                    .position(|parameter| *parameter == name)
                    .ok_or_else(|| format!("unknown expression identifier '{name}'"))?;
                Ok((
                    vec![Instruction::Parameter(index as u16)],
                    self.parameter_types[index],
                ))
            }
            ExprToken::LParen => {
                if self.depth >= MAX_EXPRESSION_DEPTH {
                    return Err(format!(
                        "return expression exceeds maximum nesting depth {MAX_EXPRESSION_DEPTH}"
                    ));
                }
                self.depth += 1;
                let expression = self.parse_equality()?;
                self.depth -= 1;
                if !self.eat(&ExprToken::RParen) {
                    return Err("expected ')' in return expression".to_string());
                }
                Ok(expression)
            }
            token => Err(format!("expected expression value, found {token:?}")),
        }
    }

    fn current(&self) -> &ExprToken {
        &self.tokens[self.position]
    }

    fn bump(&mut self) -> ExprToken {
        let token = self.current().clone();
        if token != ExprToken::Eof {
            self.position += 1;
        }
        token
    }

    fn eat(&mut self, expected: &ExprToken) -> bool {
        if self.current() == expected {
            self.bump();
            true
        } else {
            false
        }
    }
}

const MAX_EXPRESSION_SOURCE_BYTES: usize = 65_536;
const MAX_EXPRESSION_TOKENS: usize = 4_096;
const MAX_EXPRESSION_DEPTH: usize = 128;

fn require_u64_pair(left: ValueType, right: ValueType, operation: &str) -> Result<(), String> {
    if left != ValueType::U64 || right != ValueType::U64 {
        return Err(format!("{operation} currently requires two u64 operands"));
    }
    Ok(())
}

fn lex_expression(source: &str) -> Result<Vec<ExprToken>, String> {
    if source.len() > MAX_EXPRESSION_SOURCE_BYTES {
        return Err(format!(
            "return expression exceeds {MAX_EXPRESSION_SOURCE_BYTES} bytes"
        ));
    }
    let bytes = source.as_bytes();
    let mut position = 0usize;
    let mut tokens = Vec::new();
    while position < bytes.len() {
        let byte = bytes[position];
        if byte.is_ascii_whitespace() {
            position += 1;
            continue;
        }
        if byte.is_ascii_digit() {
            let start = position;
            position += 1;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                position += 1;
            }
            tokens.push(ExprToken::Int(source[start..position].to_string()));
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = position;
            position += 1;
            while position < bytes.len()
                && (bytes[position].is_ascii_alphanumeric() || bytes[position] == b'_')
            {
                position += 1;
            }
            let name = &source[start..position];
            tokens.push(match name {
                "true" => ExprToken::Bool(true),
                "false" => ExprToken::Bool(false),
                _ => ExprToken::Ident(name.to_string()),
            });
            continue;
        }
        let token = match byte {
            b'(' => ExprToken::LParen,
            b')' => ExprToken::RParen,
            b'+' => ExprToken::Plus,
            b'-' => ExprToken::Minus,
            b'*' => ExprToken::Star,
            b'/' => ExprToken::Slash,
            b'<' => ExprToken::Lt,
            b'=' if bytes.get(position + 1) == Some(&b'=') => {
                position += 1;
                ExprToken::EqEq
            }
            _ => return Err(format!("unsupported expression byte 0x{byte:02x}")),
        };
        tokens.push(token);
        position += 1;
    }
    if tokens.len() > MAX_EXPRESSION_TOKENS {
        return Err(format!(
            "return expression exceeds {MAX_EXPRESSION_TOKENS} tokens"
        ));
    }
    tokens.push(ExprToken::Eof);
    Ok(tokens)
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
            "contract C { pub fn x() -> u64 { return call(); } }",
            "contract C { pub async fn x() -> u64 { return 1; } }",
        ] {
            assert!(compile(unsupported).is_err(), "compiled {unsupported}");
        }
    }

    #[test]
    fn compiles_precedence_and_executes_checked_u64_expressions() {
        let artifact = compile(
            "contract C { pub fn calculate(value: u64) -> u64 { return value + 2 * 3; } pub fn small(value: u64) -> bool { return value < 10; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let vm = Vm::default();
        let result = vm
            .execute(&bytes, "calculate", &[word_from_u64(36)], 100)
            .unwrap();
        assert_eq!(result.return_value, word_from_u64(42));
        assert_eq!(
            vm.execute(&bytes, "small", &[word_from_u64(9)], 100)
                .unwrap()
                .return_value,
            word_from_u64(1)
        );
    }

    #[test]
    fn rejects_expression_type_errors_and_runtime_faults() {
        assert!(
            compile("contract C { pub fn bad(flag: bool) -> u64 { return flag + 1; } }")
                .unwrap_err()
                .to_string()
                .contains("requires two u64 operands")
        );
        assert!(
            compile("contract C { pub fn bad(value: u64) -> bool { return value + 1; } }")
                .unwrap_err()
                .to_string()
                .contains("expression has type u64, expected bool")
        );

        let artifact = compile(
            "contract C { pub fn divide(value: u64, divisor: u64) -> u64 { return value / divisor; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        assert!(Vm::default()
            .execute(
                &bytes,
                "divide",
                &[word_from_u64(42), word_from_u64(0)],
                100,
            )
            .is_err());
    }

    #[test]
    fn rejects_excessive_expression_depth_and_size() {
        let nested = format!(
            "contract C {{ pub fn x() -> u64 {{ return {}1{}; }} }}",
            "(".repeat(MAX_EXPRESSION_DEPTH + 1),
            ")".repeat(MAX_EXPRESSION_DEPTH + 1)
        );
        assert!(compile(&nested)
            .unwrap_err()
            .to_string()
            .contains("maximum nesting depth"));

        let oversized = format!(
            "contract C {{ pub fn x() -> u64 {{ return {}; }} }}",
            "1+".repeat(MAX_EXPRESSION_TOKENS) + "1"
        );
        assert!(compile(&oversized)
            .unwrap_err()
            .to_string()
            .contains("tokens"));
    }
}
