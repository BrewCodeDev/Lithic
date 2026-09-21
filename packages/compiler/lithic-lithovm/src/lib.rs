//! Fail-closed Lithic-to-native-LithoVM backend.
//!
//! The backend emits a versioned, strictly decoded native artifact. Unsupported
//! declarations reject the whole compilation; no source behavior is silently
//! discarded.

use lithic_syntax::{Contract, Item, Type};
use lithovm_bytecode::{
    EventDefinition, Function, Instruction, Program, ReturnValue, Statement, StorageField,
    ValueType, MAX_BLOCK_DEPTH, MAX_LOCALS, MAX_STATEMENTS, VERSION,
};
use serde::Serialize;
use std::fmt;

pub const TARGET: &str = "lithovm-native-v7";

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
    let mut storage = Vec::new();
    let mut events = Vec::new();

    for item in &contract.items {
        if let Item::State(state) = item {
            for field in &state.fields {
                match lower_type(&field.ty) {
                    Ok(value_type) => storage.push(StorageField {
                        name: field.name.clone(),
                        value_type,
                    }),
                    Err(message) => errors.push(format!("state field '{}': {message}", field.name)),
                }
            }
        }
    }

    for item in &contract.items {
        if let Item::Event(event) = item {
            let mut fields = Vec::new();
            for field in &event.fields {
                match lower_type(&field.ty) {
                    Ok(value_type) => fields.push(StorageField {
                        name: field.name.clone(),
                        value_type,
                    }),
                    Err(message) => errors.push(format!(
                        "event '{}' field '{}': {message}",
                        event.name, field.name
                    )),
                }
            }
            events.push(EventDefinition {
                name: event.name.clone(),
                fields,
            });
            abi.push(serde_json::json!({
                "type": "event",
                "name": event.name,
                "inputs": event.fields.iter().filter_map(|field| lower_type(&field.ty).ok().map(|value_type| {
                    serde_json::json!({"name": field.name, "type": value_type.name()})
                })).collect::<Vec<_>>()
            }));
        }
    }

    for item in &contract.items {
        match item {
            Item::Const(_) => errors.push(
                "contract constants are not supported by native LithoVM bytecode v7".to_string(),
            ),
            Item::Event(_) => {}
            Item::Func(function) => match compile_function(function, &storage, &events) {
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

    let program = Program {
        storage,
        events,
        functions,
    };
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
    storage: &[StorageField],
    events: &[EventDefinition],
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
    let return_value = parse_body(function, return_type, &parameters, storage, events)?;
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
            other => Err(format!("type '{other}' has no native LithoVM v7 lowering")),
        },
        Type::Map(_, _) | Type::Vec(_) => Err("collection types are unsupported".to_string()),
    }
}

fn lower_named_type(name: &str) -> Result<ValueType, String> {
    match name {
        "u64" => Ok(ValueType::U64),
        "u256" => Ok(ValueType::U256),
        "bool" => Ok(ValueType::Bool),
        "address" => Ok(ValueType::Address),
        "bytes32" => Ok(ValueType::Bytes32),
        other => Err(format!("type '{other}' has no native LithoVM v7 lowering")),
    }
}

fn parse_body(
    function: &lithic_syntax::FuncDecl,
    return_type: ValueType,
    parameter_types: &[ValueType],
    storage: &[StorageField],
    events: &[EventDefinition],
) -> Result<ReturnValue, String> {
    let body = function.body_src.trim();
    if !starts_with_keyword(body, "let")
        && !starts_with_keyword(body, "if")
        && !starts_with_keyword(body, "emit")
        && !body.starts_with("transfer_native(")
        && !body.starts_with("call_contract(")
        && !body.starts_with("self.")
    {
        return parse_return(function, return_type, parameter_types, storage);
    }
    let parameter_names = function
        .params
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<Vec<_>>();
    let mut parser = BodyParser {
        source: body,
        position: 0,
        parameter_names,
        parameter_types,
        local_names: Vec::new(),
        local_types: Vec::new(),
        storage,
        events,
        statement_count: 0,
        return_type,
    };
    let statements = parser.parse_block(false, 0)?;
    Ok(ReturnValue::Statements(statements))
}

fn starts_with_keyword(source: &str, keyword: &str) -> bool {
    source
        .strip_prefix(keyword)
        .and_then(|remaining| remaining.as_bytes().first())
        .is_some_and(u8::is_ascii_whitespace)
}

struct BodyParser<'a> {
    source: &'a str,
    position: usize,
    parameter_names: Vec<&'a str>,
    parameter_types: &'a [ValueType],
    local_names: Vec<String>,
    local_types: Vec<ValueType>,
    storage: &'a [StorageField],
    events: &'a [EventDefinition],
    statement_count: usize,
    return_type: ValueType,
}

impl BodyParser<'_> {
    fn parse_block(&mut self, nested: bool, depth: usize) -> Result<Vec<Statement>, String> {
        if depth > MAX_BLOCK_DEPTH {
            return Err(format!(
                "statement nesting exceeds maximum depth {MAX_BLOCK_DEPTH}"
            ));
        }
        let mut statements = Vec::new();
        let mut terminal = false;
        loop {
            self.skip_whitespace();
            if nested && self.peek_byte() == Some(b'}') {
                self.position += 1;
                if !terminal {
                    return Err("branch does not return on every path".to_string());
                }
                return Ok(statements);
            }
            if self.position == self.source.len() {
                if nested {
                    return Err("unterminated statement block".to_string());
                }
                if !terminal {
                    return Err("function does not return on every path".to_string());
                }
                return Ok(statements);
            }
            if terminal {
                return Err("unreachable statement after terminal return or branch".to_string());
            }

            let statement = if self.consume_keyword("let") {
                self.parse_let()?
            } else if self.consume_keyword("return") {
                terminal = true;
                self.parse_return_statement()?
            } else if self.consume_keyword("if") {
                terminal = true;
                self.parse_if(depth)?
            } else if self.consume_keyword("emit") {
                self.parse_emit()?
            } else if self.consume_keyword("transfer_native") {
                self.parse_transfer()?
            } else if self.consume_keyword("call_contract") {
                self.parse_call()?
            } else if self.consume_self_prefix() {
                self.parse_store()?
            } else {
                return Err(format!("unsupported statement near '{}'", self.preview()));
            };
            self.statement_count += 1;
            if self.statement_count > MAX_STATEMENTS {
                return Err(format!("function exceeds {MAX_STATEMENTS} statements"));
            }
            statements.push(statement);
        }
    }

    fn parse_let(&mut self) -> Result<Statement, String> {
        self.skip_whitespace();
        if self.consume_keyword("mut") {
            return Err("mutable local bindings are not supported yet".to_string());
        }
        let name = self.parse_identifier()?;
        if self.parameter_names.contains(&name.as_str()) || self.local_names.contains(&name) {
            return Err(format!("duplicate local binding '{name}'"));
        }
        self.skip_whitespace();
        let annotated_type = if self.consume_byte(b':') {
            self.skip_whitespace();
            Some(lower_named_type(&self.parse_identifier()?)?)
        } else {
            None
        };
        self.skip_whitespace();
        self.expect_byte(b'=', "expected '=' in local binding")?;
        let expression_source = self.take_expression_until(b';')?.to_owned();
        let (expression, inferred_type) = self.compile_expression(&expression_source)?;
        let value_type = annotated_type.unwrap_or(inferred_type);
        if value_type != inferred_type {
            return Err(format!(
                "local binding '{name}' has type {}, expression has type {}",
                value_type.name(),
                inferred_type.name()
            ));
        }
        if self.local_names.len() >= MAX_LOCALS {
            return Err(format!("function exceeds {MAX_LOCALS} local bindings"));
        }
        self.local_names.push(name);
        self.local_types.push(value_type);
        Ok(Statement::Let {
            value_type,
            expression,
        })
    }

    fn parse_return_statement(&mut self) -> Result<Statement, String> {
        let expression_source = self.take_expression_until(b';')?.to_owned();
        let (expression, expression_type) = self.compile_expression(&expression_source)?;
        if expression_type != self.return_type {
            return Err(format!(
                "return expression has type {}, expected {}",
                expression_type.name(),
                self.return_type.name()
            ));
        }
        Ok(Statement::Return(expression))
    }

    fn parse_store(&mut self) -> Result<Statement, String> {
        let field_name = self.parse_identifier()?;
        let field = self
            .storage
            .iter()
            .position(|candidate| candidate.name == field_name)
            .ok_or_else(|| format!("unknown storage field '{field_name}'"))?;
        self.skip_whitespace();
        self.expect_byte(b'=', "expected '=' in storage assignment")?;
        let expression_source = self.take_expression_until(b';')?.to_owned();
        let (expression, expression_type) = self.compile_expression(&expression_source)?;
        let field_type = self.storage[field].value_type;
        if expression_type != field_type {
            return Err(format!(
                "storage field '{field_name}' has type {}, expression has type {}",
                field_type.name(),
                expression_type.name()
            ));
        }
        Ok(Statement::Store {
            field: field as u16,
            expression,
        })
    }

    fn parse_emit(&mut self) -> Result<Statement, String> {
        let event_name = self.parse_identifier()?;
        let event = self
            .events
            .iter()
            .position(|candidate| candidate.name == event_name)
            .ok_or_else(|| format!("unknown event '{event_name}'"))?;
        self.skip_whitespace();
        self.expect_byte(b'{', "expected '{' after event name")?;
        let definition = &self.events[event];
        let mut values = Vec::with_capacity(definition.fields.len());
        if definition.fields.is_empty() {
            self.skip_whitespace();
            self.expect_byte(b'}', "expected '}' after empty event")?;
            self.skip_whitespace();
            self.consume_byte(b';');
            return Ok(Statement::Emit {
                event: event as u16,
                values,
            });
        }
        for (index, field) in definition.fields.iter().enumerate() {
            self.skip_whitespace();
            let supplied_name = self.parse_identifier()?;
            if supplied_name != field.name {
                return Err(format!(
                    "event '{event_name}' expected field '{}', found '{supplied_name}'",
                    field.name
                ));
            }
            self.skip_whitespace();
            self.expect_byte(b':', "expected ':' after event field name")?;
            let terminator = if index + 1 == definition.fields.len() {
                b'}'
            } else {
                b','
            };
            let expression_source = self.take_expression_until(terminator)?.to_owned();
            let (expression, expression_type) = self.compile_expression(&expression_source)?;
            if expression_type != field.value_type {
                return Err(format!(
                    "event '{}' field '{}' has type {}, expression has type {}",
                    event_name,
                    field.name,
                    field.value_type.name(),
                    expression_type.name()
                ));
            }
            values.push(expression);
        }
        self.skip_whitespace();
        self.consume_byte(b';');
        Ok(Statement::Emit {
            event: event as u16,
            values,
        })
    }

    fn parse_transfer(&mut self) -> Result<Statement, String> {
        self.skip_whitespace();
        self.expect_byte(b'(', "expected '(' after transfer_native")?;
        let recipient_source = self.take_expression_until(b',')?.to_owned();
        let (recipient, recipient_type) = self.compile_expression(&recipient_source)?;
        if recipient_type != ValueType::Address {
            return Err(format!(
                "transfer recipient has type {}, expected address",
                recipient_type.name()
            ));
        }
        let amount_source = self.take_expression_until(b')')?.to_owned();
        let (amount, amount_type) = self.compile_expression(&amount_source)?;
        if amount_type != ValueType::U256 {
            return Err(format!(
                "transfer amount has type {}, expected u256",
                amount_type.name()
            ));
        }
        self.skip_whitespace();
        self.expect_byte(b';', "expected ';' after transfer_native")?;
        Ok(Statement::Transfer { recipient, amount })
    }

    fn parse_call(&mut self) -> Result<Statement, String> {
        self.skip_whitespace();
        self.expect_byte(b'(', "expected '(' after call_contract")?;
        let target_source = self.take_expression_until(b',')?.to_owned();
        let (target, target_type) = self.compile_expression(&target_source)?;
        if target_type != ValueType::Address {
            return Err(format!(
                "contract call target has type {}, expected address",
                target_type.name()
            ));
        }
        let selector_source = self.take_expression_until(b',')?.to_owned();
        let (selector, selector_type) = self.compile_expression(&selector_source)?;
        if selector_type != ValueType::Bytes32 {
            return Err(format!(
                "contract call selector has type {}, expected bytes32",
                selector_type.name()
            ));
        }
        let value_source = self.take_expression_until(b')')?.to_owned();
        let (value, value_type) = self.compile_expression(&value_source)?;
        if value_type != ValueType::U256 {
            return Err(format!(
                "contract call value has type {}, expected u256",
                value_type.name()
            ));
        }
        self.skip_whitespace();
        self.expect_byte(b';', "expected ';' after call_contract")?;
        Ok(Statement::Call {
            target,
            selector,
            value,
        })
    }

    fn parse_if(&mut self, depth: usize) -> Result<Statement, String> {
        let condition_source = self.take_expression_until(b'{')?.to_owned();
        let (condition, condition_type) = self.compile_expression(&condition_source)?;
        if condition_type != ValueType::Bool {
            return Err(format!(
                "if condition has type {}, expected bool",
                condition_type.name()
            ));
        }

        let inherited_local_count = self.local_names.len();
        let then_branch = self.parse_block(true, depth + 1)?;
        self.local_names.truncate(inherited_local_count);
        self.local_types.truncate(inherited_local_count);

        self.skip_whitespace();
        if !self.consume_keyword("else") {
            return Err("if statement requires an else branch".to_string());
        }
        self.skip_whitespace();
        self.expect_byte(b'{', "expected '{' after else")?;
        let else_branch = self.parse_block(true, depth + 1)?;
        self.local_names.truncate(inherited_local_count);
        self.local_types.truncate(inherited_local_count);
        Ok(Statement::If {
            condition,
            then_branch,
            else_branch,
        })
    }

    fn compile_expression(&self, source: &str) -> Result<(Vec<Instruction>, ValueType), String> {
        ExpressionParser::new(
            source,
            &self.parameter_names,
            self.parameter_types,
            &self.local_names,
            &self.local_types,
            self.storage,
        )?
        .parse()
    }

    fn take_expression_until(&mut self, terminator: u8) -> Result<&str, String> {
        self.skip_whitespace();
        let start = self.position;
        let mut parentheses = 0usize;
        while let Some(byte) = self.peek_byte() {
            match byte {
                value if value == terminator && parentheses == 0 => {
                    let expression = self.source[start..self.position].trim();
                    self.position += 1;
                    if expression.is_empty() {
                        return Err("expected expression".to_string());
                    }
                    return Ok(expression);
                }
                b'(' => parentheses += 1,
                b')' => {
                    parentheses = parentheses
                        .checked_sub(1)
                        .ok_or_else(|| "unmatched ')' in expression".to_string())?;
                }
                _ => {}
            }
            self.position += 1;
        }
        Err(format!(
            "expected '{}' after expression",
            terminator as char
        ))
    }

    fn parse_identifier(&mut self) -> Result<String, String> {
        self.skip_whitespace();
        let start = self.position;
        let Some(first) = self.peek_byte() else {
            return Err("expected identifier".to_string());
        };
        if !first.is_ascii_alphabetic() && first != b'_' {
            return Err("expected identifier".to_string());
        }
        self.position += 1;
        while matches!(self.peek_byte(), Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.position += 1;
        }
        Ok(self.source[start..self.position].to_string())
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let remaining = &self.source[self.position..];
        if !remaining.starts_with(keyword) {
            return false;
        }
        let boundary = remaining.as_bytes().get(keyword.len()).copied();
        if matches!(boundary, Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_') {
            return false;
        }
        self.position += keyword.len();
        true
    }

    fn consume_self_prefix(&mut self) -> bool {
        if self.source[self.position..].starts_with("self.") {
            self.position += "self.".len();
            true
        } else {
            false
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.peek_byte() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect_byte(&mut self, expected: u8, message: &str) -> Result<(), String> {
        if self.consume_byte(expected) {
            Ok(())
        } else {
            Err(message.to_string())
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(byte) if byte.is_ascii_whitespace()) {
            self.position += 1;
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.position).copied()
    }

    fn preview(&self) -> &str {
        let end = self.source.len().min(self.position + 24);
        &self.source[self.position..end]
    }
}

fn parse_return(
    function: &lithic_syntax::FuncDecl,
    return_type: ValueType,
    parameter_types: &[ValueType],
    storage: &[StorageField],
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
        &[],
        &[],
        storage,
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
    local_names: &'a [String],
    local_types: &'a [ValueType],
    storage: &'a [StorageField],
}

impl<'a> ExpressionParser<'a> {
    fn new(
        source: &str,
        parameter_names: &'a [&'a str],
        parameter_types: &'a [ValueType],
        local_names: &'a [String],
        local_types: &'a [ValueType],
        storage: &'a [StorageField],
    ) -> Result<Self, String> {
        Ok(Self {
            tokens: lex_expression(source)?,
            position: 0,
            depth: 0,
            parameter_names,
            parameter_types,
            local_names,
            local_types,
            storage,
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
                if let Some((instruction, value_type)) = match name.as_str() {
                    "msg.sender" => Some((Instruction::MessageSender, ValueType::Address)),
                    "msg.value" => Some((Instruction::MessageValue, ValueType::U256)),
                    "block.height" => Some((Instruction::BlockHeight, ValueType::U64)),
                    "block.timestamp" => Some((Instruction::BlockTimestamp, ValueType::U64)),
                    "chain.id" => Some((Instruction::ChainId, ValueType::U64)),
                    _ => None,
                } {
                    return Ok((vec![instruction], value_type));
                }
                if let Some(field_name) = name.strip_prefix("self.") {
                    let index = self
                        .storage
                        .iter()
                        .position(|field| field.name == field_name)
                        .ok_or_else(|| format!("unknown storage field '{field_name}'"))?;
                    return Ok((
                        vec![Instruction::Storage(index as u16)],
                        self.storage[index].value_type,
                    ));
                }
                if let Some(index) = self
                    .parameter_names
                    .iter()
                    .position(|parameter| *parameter == name)
                {
                    return Ok((
                        vec![Instruction::Parameter(index as u16)],
                        self.parameter_types[index],
                    ));
                }
                if let Some(index) = self.local_names.iter().position(|local| *local == name) {
                    return Ok((
                        vec![Instruction::Local(index as u16)],
                        self.local_types[index],
                    ));
                }
                Err(format!("unknown expression identifier '{name}'"))
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
            if bytes.get(position) == Some(&b'.') {
                position += 1;
                let Some(first) = bytes.get(position) else {
                    return Err("expected identifier after '.'".to_string());
                };
                if !first.is_ascii_alphabetic() && *first != b'_' {
                    return Err("expected identifier after '.'".to_string());
                }
                position += 1;
                while position < bytes.len()
                    && (bytes[position].is_ascii_alphanumeric() || bytes[position] == b'_')
                {
                    position += 1;
                }
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
    use lithovm::{ExecutionContext, Storage, Vm, BASE_CALL_GAS, PARAMETER_GAS};

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
            "contract C { state { values: map<address, u64>; } pub fn x() -> u64 { return 1; } }",
            "contract C { event Seen { values: map<address, u64> } pub fn x() -> u64 { return 1; } }",
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

    #[test]
    fn compiles_locals_and_executes_only_the_selected_branch() {
        let artifact = compile(
            "contract C { pub fn choose(value: u64, limit: u64) -> u64 { let doubled: u64 = value * 2; if doubled < limit { return doubled; } else { let fallback = limit + 1; return fallback; } } }",
        )
        .unwrap();
        assert_eq!(artifact.target, "lithovm-native-v7");
        assert_eq!(artifact.bytecode_version, 7);
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let vm = Vm::default();

        let selected = vm
            .execute(
                &bytes,
                "choose",
                &[word_from_u64(4), word_from_u64(10)],
                100,
            )
            .unwrap();
        assert_eq!(selected.return_value, word_from_u64(8));

        let fallback = vm
            .execute(
                &bytes,
                "choose",
                &[word_from_u64(6), word_from_u64(10)],
                100,
            )
            .unwrap();
        assert_eq!(fallback.return_value, word_from_u64(11));
        assert!(fallback.gas_used > selected.gas_used);

        let lazy = compile(
            "contract C { pub fn safe(flag: bool) -> u64 { if flag { return 7; } else { return 1 / 0; } } }",
        )
        .unwrap();
        let lazy_bytes = hex::decode(&lazy.bytecode[2..]).unwrap();
        assert_eq!(
            vm.execute(&lazy_bytes, "safe", &[word_from_u64(1)], 100)
                .unwrap()
                .return_value,
            word_from_u64(7)
        );
        assert!(vm
            .execute(&lazy_bytes, "safe", &[word_from_u64(0)], 100)
            .is_err());
    }

    #[test]
    fn rejects_invalid_local_and_control_flow_bodies() {
        for (source, expected) in [
            (
                "contract C { pub fn x(value: u64) -> u64 { let value = 1; return value; } }",
                "duplicate local binding",
            ),
            (
                "contract C { pub fn x(value: u64) -> u64 { if value < 1 { return 1; } } }",
                "requires an else branch",
            ),
            (
                "contract C { pub fn x(value: u64) -> u64 { if value { return 1; } else { return 2; } } }",
                "if condition has type u64",
            ),
            (
                "contract C { pub fn x(value: u64) -> u64 { let mut next = value; return next; } }",
                "mutable local bindings",
            ),
        ] {
            assert!(
                compile(source).unwrap_err().to_string().contains(expected),
                "missing '{expected}' for {source}"
            );
        }
    }

    #[test]
    fn scalar_storage_commits_atomically_and_rolls_back_failures() {
        let artifact = compile(
            "contract Counter { state { count: u64; } pub fn get() -> u64 { return self.count; } pub fn set(value: u64) -> u64 { self.count = value; return self.count; } pub fn fail(value: u64) -> u64 { self.count = value; self.count = value / 0; return self.count; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let vm = Vm::default();
        let mut storage = Storage::default();

        assert!(vm.execute(&bytes, "get", &[], 100).is_err());
        assert_eq!(
            vm.execute_with_storage(&bytes, "get", &[], 100, &mut storage)
                .unwrap()
                .return_value,
            word_from_u64(0)
        );
        assert_eq!(
            vm.execute_with_storage(&bytes, "set", &[word_from_u64(41)], 100, &mut storage,)
                .unwrap()
                .return_value,
            word_from_u64(41)
        );
        assert_eq!(storage.get("count"), Some(&word_from_u64(41)));

        assert!(vm
            .execute_with_storage(
                &bytes,
                "set",
                &[word_from_u64(77)],
                BASE_CALL_GAS + PARAMETER_GAS + 2,
                &mut storage,
            )
            .is_err());
        assert_eq!(storage.get("count"), Some(&word_from_u64(41)));

        assert!(vm
            .execute_with_storage(&bytes, "fail", &[word_from_u64(99)], 100, &mut storage,)
            .is_err());
        assert_eq!(storage.get("count"), Some(&word_from_u64(41)));
    }

    #[test]
    fn rejects_unknown_or_mistyped_storage_access() {
        for (source, expected) in [
            (
                "contract C { state { value: u64; } pub fn x() -> u64 { return self.missing; } }",
                "unknown storage field 'missing'",
            ),
            (
                "contract C { state { value: bool; } pub fn x(input: u64) -> bool { self.value = input; return self.value; } }",
                "storage field 'value' has type bool",
            ),
        ] {
            assert!(
                compile(source).unwrap_err().to_string().contains(expected),
                "missing '{expected}' for {source}"
            );
        }
    }

    #[test]
    fn compiles_and_executes_explicit_host_context() {
        let artifact = compile(
            "contract Context { pub fn sender() -> address { return msg.sender; } pub fn value() -> u256 { return msg.value; } pub fn height() -> u64 { return block.height; } pub fn timestamp() -> u64 { return block.timestamp; } pub fn chain() -> u64 { return chain.id; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let mut caller = [0; 32];
        caller[12..].copy_from_slice(&[7; 20]);
        let context = ExecutionContext {
            caller,
            value: word_from_u64(25),
            block_height: 91,
            block_timestamp: 1_725_000_000,
            chain_id: 9005,
            contract_balance: [0; 32],
            call_depth: 0,
        };
        let vm = Vm::default();

        assert!(vm.execute(&bytes, "sender", &[], 100).is_err());
        for (name, expected) in [
            ("sender", caller),
            ("value", word_from_u64(25)),
            ("height", word_from_u64(91)),
            ("timestamp", word_from_u64(1_725_000_000)),
            ("chain", word_from_u64(9005)),
        ] {
            assert_eq!(
                vm.execute_with_context(&bytes, name, &[], 100, &context)
                    .unwrap()
                    .return_value,
                expected
            );
        }
    }

    #[test]
    fn context_storage_execution_remains_transactional() {
        let artifact = compile(
            "contract ContextState { state { last: u64; } pub fn record() -> u64 { self.last = block.timestamp; return self.last; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let vm = Vm::default();
        let mut storage = Storage::default();
        let context = ExecutionContext {
            block_timestamp: 1234,
            chain_id: 9005,
            ..ExecutionContext::default()
        };

        assert!(vm
            .execute_with_storage(&bytes, "record", &[], 100, &mut storage)
            .is_err());
        assert_eq!(storage.get("last"), None);
        assert_eq!(
            vm.execute_with_storage_and_context(
                &bytes,
                "record",
                &[],
                100,
                &mut storage,
                &context,
            )
            .unwrap()
            .return_value,
            word_from_u64(1234)
        );
        assert_eq!(storage.get("last"), Some(&word_from_u64(1234)));
    }

    #[test]
    fn typed_events_are_emitted_in_order_after_success() {
        let artifact = compile(
            "contract Emitter { event Changed { account: address, value: u64 } pub fn change(account: address, value: u64) -> u64 { emit Changed { account: account, value: value }; return value; } }",
        )
        .unwrap();
        assert_eq!(artifact.abi[0]["type"], "event");
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let mut account = [0; 32];
        account[12..].copy_from_slice(&[9; 20]);
        let result = Vm::default()
            .execute(&bytes, "change", &[account, word_from_u64(42)], 100)
            .unwrap();

        assert_eq!(result.return_value, word_from_u64(42));
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].name, "Changed");
        assert_eq!(result.events[0].fields[0].0, "account");
        assert_eq!(result.events[0].fields[0].2, account);
        assert_eq!(result.events[0].fields[1].2, word_from_u64(42));
    }

    #[test]
    fn event_schema_and_emissions_fail_closed() {
        for (source, expected) in [
            (
                "contract C { event Seen { value: u64 } pub fn x() -> u64 { emit Missing { value: 1 }; return 1; } }",
                "unknown event 'Missing'",
            ),
            (
                "contract C { event Seen { value: u64 } pub fn x() -> u64 { emit Seen { value: true }; return 1; } }",
                "field 'value' has type u64",
            ),
            (
                "contract C { event Seen { value: u64, account: address } pub fn x() -> u64 { emit Seen { account: 0x0000000000000000000000000000000000000000, value: 1 }; return 1; } }",
                "expected field 'value'",
            ),
        ] {
            assert!(
                compile(source).unwrap_err().to_string().contains(expected),
                "missing '{expected}' for {source}"
            );
        }
    }

    #[test]
    fn native_transfers_are_staged_and_balance_checked() {
        let artifact = compile(
            "contract Payout { pub fn pay(to: address, amount: u256) -> u256 { transfer_native(to, amount); return amount; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let mut recipient = [0; 32];
        recipient[12..].copy_from_slice(&[3; 20]);
        let context = ExecutionContext {
            contract_balance: word_from_u64(100),
            chain_id: 9005,
            ..ExecutionContext::default()
        };
        let vm = Vm::default();

        assert!(vm
            .execute(&bytes, "pay", &[recipient, word_from_u64(40)], 100,)
            .is_err());
        let result = vm
            .execute_with_context(
                &bytes,
                "pay",
                &[recipient, word_from_u64(40)],
                100,
                &context,
            )
            .unwrap();
        assert_eq!(result.transfers.len(), 1);
        assert_eq!(result.transfers[0].recipient, recipient);
        assert_eq!(result.transfers[0].amount, word_from_u64(40));

        assert!(vm
            .execute_with_context(
                &bytes,
                "pay",
                &[recipient, word_from_u64(101)],
                100,
                &context,
            )
            .is_err());

        let twice = compile(
            "contract Payout { pub fn pay(to: address, first: u256, second: u256) -> u256 { transfer_native(to, first); transfer_native(to, second); return second; } }",
        )
        .unwrap();
        let twice_bytes = hex::decode(&twice.bytecode[2..]).unwrap();
        assert!(vm
            .execute_with_context(
                &twice_bytes,
                "pay",
                &[recipient, word_from_u64(60), word_from_u64(41)],
                200,
                &context,
            )
            .is_err());
    }

    #[test]
    fn native_transfer_types_fail_closed() {
        for (source, expected) in [
            (
                "contract C { pub fn x(to: u64, amount: u256) -> u256 { transfer_native(to, amount); return amount; } }",
                "recipient has type u64",
            ),
            (
                "contract C { pub fn x(to: address, amount: u64) -> u64 { transfer_native(to, amount); return amount; } }",
                "amount has type u64",
            ),
        ] {
            assert!(
                compile(source).unwrap_err().to_string().contains(expected),
                "missing '{expected}' for {source}"
            );
        }
    }

    #[test]
    fn contract_calls_are_staged_with_depth_and_balance_limits() {
        let artifact = compile(
            "contract Caller { pub fn invoke(target: address, selector: bytes32, value: u256) -> u256 { call_contract(target, selector, value); return value; } }",
        )
        .unwrap();
        let bytes = hex::decode(&artifact.bytecode[2..]).unwrap();
        let mut target = [0; 32];
        target[12..].copy_from_slice(&[4; 20]);
        let selector = [7; 32];
        let context = ExecutionContext {
            contract_balance: word_from_u64(100),
            call_depth: 4,
            chain_id: 9005,
            ..ExecutionContext::default()
        };
        let vm = Vm::default();

        let result = vm
            .execute_with_context(
                &bytes,
                "invoke",
                &[target, selector, word_from_u64(30)],
                200,
                &context,
            )
            .unwrap();
        assert_eq!(result.calls.len(), 1);
        assert_eq!(result.calls[0].target, target);
        assert_eq!(result.calls[0].selector, selector);
        assert_eq!(result.calls[0].value, word_from_u64(30));
        assert_eq!(result.calls[0].depth, 5);

        let depth_limited = ExecutionContext {
            call_depth: lithovm::MAX_CALL_DEPTH,
            ..context.clone()
        };
        assert!(vm
            .execute_with_context(
                &bytes,
                "invoke",
                &[target, selector, word_from_u64(1)],
                200,
                &depth_limited,
            )
            .is_err());
        assert!(vm
            .execute_with_context(
                &bytes,
                "invoke",
                &[target, selector, word_from_u64(101)],
                200,
                &context,
            )
            .is_err());

        let mixed = compile(
            "contract Caller { pub fn invoke(recipient: address, target: address, selector: bytes32, transfer_value: u256, call_value: u256) -> u256 { transfer_native(recipient, transfer_value); call_contract(target, selector, call_value); return call_value; } }",
        )
        .unwrap();
        let mixed_bytes = hex::decode(&mixed.bytecode[2..]).unwrap();
        let result = vm
            .execute_with_context(
                &mixed_bytes,
                "invoke",
                &[
                    target,
                    target,
                    selector,
                    word_from_u64(60),
                    word_from_u64(40),
                ],
                300,
                &context,
            )
            .unwrap();
        assert_eq!(result.transfers.len(), 1);
        assert_eq!(result.calls.len(), 1);
        assert!(vm
            .execute_with_context(
                &mixed_bytes,
                "invoke",
                &[
                    target,
                    target,
                    selector,
                    word_from_u64(60),
                    word_from_u64(41),
                ],
                300,
                &context,
            )
            .is_err());
    }

    #[test]
    fn contract_call_types_fail_closed() {
        for (source, expected) in [
            (
                "contract C { pub fn x(target: u64, selector: bytes32, value: u256) -> u256 { call_contract(target, selector, value); return value; } }",
                "target has type u64",
            ),
            (
                "contract C { pub fn x(target: address, selector: u64, value: u256) -> u256 { call_contract(target, selector, value); return value; } }",
                "selector has type u64",
            ),
            (
                "contract C { pub fn x(target: address, selector: bytes32, value: u64) -> u64 { call_contract(target, selector, value); return value; } }",
                "value has type u64",
            ),
        ] {
            assert!(
                compile(source).unwrap_err().to_string().contains(expected),
                "missing '{expected}' for {source}"
            );
        }
    }
}
