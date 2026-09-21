use anyhow::{anyhow, bail, Result};

pub const MAGIC: &[u8; 7] = b"LITHOVM";
pub const LEGACY_VERSION: u8 = 1;
pub const VERSION: u8 = 2;
pub const MAX_FUNCTIONS: usize = 1024;
pub const MAX_PARAMETERS: usize = 64;
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_LOCALS: usize = 256;
pub const MAX_STATEMENTS: usize = 4096;
pub const MAX_BLOCK_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueType {
    U64 = 1,
    U256 = 2,
    Bool = 3,
    Address = 4,
    Bytes32 = 5,
}

impl ValueType {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::U64),
            2 => Ok(Self::U256),
            3 => Ok(Self::Bool),
            4 => Ok(Self::Address),
            5 => Ok(Self::Bytes32),
            _ => bail!("unknown LithoVM value type {value}"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::U64 => "u64",
            Self::U256 => "u256",
            Self::Bool => "bool",
            Self::Address => "address",
            Self::Bytes32 => "bytes32",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReturnValue {
    Constant([u8; 32]),
    Parameter(u16),
    Expression(Vec<Instruction>),
    Statements(Vec<Statement>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    Let {
        value_type: ValueType,
        expression: Vec<Instruction>,
    },
    Return(Vec<Instruction>),
    If {
        condition: Vec<Instruction>,
        then_branch: Vec<Statement>,
        else_branch: Vec<Statement>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    Constant(ValueType, [u8; 32]),
    Parameter(u16),
    Local(u16),
    AddU64,
    SubU64,
    MulU64,
    DivU64,
    Eq,
    LtU64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub parameters: Vec<ValueType>,
    pub return_type: ValueType,
    pub return_value: ReturnValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub functions: Vec<Function>,
}

impl Program {
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_functions(&self.functions)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        push_u16(&mut bytes, self.functions.len())?;
        for function in &self.functions {
            push_u16(&mut bytes, function.name.len())?;
            bytes.extend_from_slice(function.name.as_bytes());
            push_u16(&mut bytes, function.parameters.len())?;
            bytes.extend(function.parameters.iter().map(|value| *value as u8));
            bytes.push(function.return_type as u8);
            match function.return_value {
                ReturnValue::Constant(word) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&word);
                }
                ReturnValue::Parameter(index) => {
                    bytes.push(2);
                    bytes.extend_from_slice(&index.to_be_bytes());
                }
                ReturnValue::Expression(ref instructions) => {
                    bytes.push(3);
                    encode_expression(&mut bytes, instructions)?;
                }
                ReturnValue::Statements(ref statements) => {
                    bytes.push(4);
                    encode_statements(&mut bytes, statements)?;
                }
            }
        }
        Ok(bytes)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Program> {
    let mut reader = Reader { bytes, position: 0 };
    if reader.take(MAGIC.len())? != MAGIC {
        bail!("invalid LithoVM bytecode magic");
    }
    let version = reader.byte()?;
    if version != LEGACY_VERSION && version != VERSION {
        bail!("unsupported LithoVM bytecode version {version}");
    }
    let function_count = reader.u16()? as usize;
    if function_count == 0 || function_count > MAX_FUNCTIONS {
        bail!("invalid LithoVM function count {function_count}");
    }
    let mut functions = Vec::with_capacity(function_count);
    for _ in 0..function_count {
        let name_len = reader.u16()? as usize;
        if name_len == 0 || name_len > MAX_NAME_BYTES {
            bail!("invalid LithoVM function name length {name_len}");
        }
        let name = std::str::from_utf8(reader.take(name_len)?)
            .map_err(|_| anyhow!("function name is not valid UTF-8"))?
            .to_owned();
        let parameter_count = reader.u16()? as usize;
        if parameter_count > MAX_PARAMETERS {
            bail!("too many LithoVM function parameters: {parameter_count}");
        }
        let mut parameters = Vec::with_capacity(parameter_count);
        for _ in 0..parameter_count {
            parameters.push(ValueType::from_byte(reader.byte()?)?);
        }
        let return_type = ValueType::from_byte(reader.byte()?)?;
        let return_value = match reader.byte()? {
            1 => {
                let mut word = [0u8; 32];
                word.copy_from_slice(reader.take(32)?);
                validate_word(return_type, &word)?;
                ReturnValue::Constant(word)
            }
            2 => {
                let index = reader.u16()?;
                let parameter_type = parameters
                    .get(index as usize)
                    .ok_or_else(|| anyhow!("return parameter index {index} is out of range"))?;
                if *parameter_type != return_type {
                    bail!(
                        "return parameter type {} does not match {}",
                        parameter_type.name(),
                        return_type.name()
                    );
                }
                ReturnValue::Parameter(index)
            }
            3 => {
                let instruction_count = reader.u16()? as usize;
                if instruction_count == 0 || instruction_count > MAX_INSTRUCTIONS {
                    bail!("invalid LithoVM instruction count {instruction_count}");
                }
                let mut instructions = Vec::with_capacity(instruction_count);
                for _ in 0..instruction_count {
                    instructions.push(decode_instruction(&mut reader, version)?);
                }
                validate_expression(&instructions, &parameters, &[], return_type)?;
                ReturnValue::Expression(instructions)
            }
            4 if version >= VERSION => {
                let statements = decode_statements(&mut reader, version, 0)?;
                validate_statements(&statements, &parameters, return_type, &[], 0)?;
                ReturnValue::Statements(statements)
            }
            opcode => bail!("unknown LithoVM return opcode {opcode}"),
        };
        functions.push(Function {
            name,
            parameters,
            return_type,
            return_value,
        });
    }
    if reader.position != bytes.len() {
        bail!("trailing bytes after LithoVM program");
    }
    validate_functions(&functions)?;
    Ok(Program { functions })
}

pub fn validate_word(value_type: ValueType, word: &[u8; 32]) -> Result<()> {
    match value_type {
        ValueType::U64 if word[..24] != [0; 24] => bail!("non-canonical u64 value"),
        ValueType::Bool if word[..31] != [0; 31] || word[31] > 1 => {
            bail!("non-canonical bool value")
        }
        ValueType::Address if word[..12] != [0; 12] => bail!("non-canonical address value"),
        _ => Ok(()),
    }
}

fn validate_functions(functions: &[Function]) -> Result<()> {
    if functions.is_empty() || functions.len() > MAX_FUNCTIONS {
        bail!("program must contain between 1 and {MAX_FUNCTIONS} functions");
    }
    for (index, function) in functions.iter().enumerate() {
        if function.name.is_empty()
            || function.name.len() > MAX_NAME_BYTES
            || !function.name.is_ascii()
            || !is_identifier(&function.name)
        {
            bail!("invalid LithoVM function name '{}'", function.name);
        }
        if function.parameters.len() > MAX_PARAMETERS {
            bail!("too many parameters in function '{}'", function.name);
        }
        if functions[..index]
            .iter()
            .any(|earlier| earlier.name == function.name)
        {
            bail!("duplicate LithoVM function name '{}'", function.name);
        }
        match function.return_value {
            ReturnValue::Constant(word) => validate_word(function.return_type, &word)?,
            ReturnValue::Parameter(parameter) => {
                let parameter_type = function
                    .parameters
                    .get(parameter as usize)
                    .ok_or_else(|| anyhow!("return parameter index is out of range"))?;
                if *parameter_type != function.return_type {
                    bail!("return parameter type does not match function return type");
                }
            }
            ReturnValue::Expression(ref instructions) => {
                validate_expression(
                    instructions,
                    &function.parameters,
                    &[],
                    function.return_type,
                )?;
            }
            ReturnValue::Statements(ref statements) => {
                validate_statements(
                    statements,
                    &function.parameters,
                    function.return_type,
                    &[],
                    0,
                )?;
            }
        }
    }
    Ok(())
}

pub const MAX_INSTRUCTIONS: usize = 4096;

fn encode_expression(bytes: &mut Vec<u8>, instructions: &[Instruction]) -> Result<()> {
    push_u16(bytes, instructions.len())?;
    for instruction in instructions {
        encode_instruction(bytes, instruction);
    }
    Ok(())
}

fn encode_statements(bytes: &mut Vec<u8>, statements: &[Statement]) -> Result<()> {
    push_u16(bytes, statements.len())?;
    for statement in statements {
        match statement {
            Statement::Let {
                value_type,
                expression,
            } => {
                bytes.push(1);
                bytes.push(*value_type as u8);
                encode_expression(bytes, expression)?;
            }
            Statement::Return(expression) => {
                bytes.push(2);
                encode_expression(bytes, expression)?;
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
            } => {
                bytes.push(3);
                encode_expression(bytes, condition)?;
                encode_statements(bytes, then_branch)?;
                encode_statements(bytes, else_branch)?;
            }
        }
    }
    Ok(())
}

fn encode_instruction(bytes: &mut Vec<u8>, instruction: &Instruction) {
    match instruction {
        Instruction::Constant(value_type, word) => {
            bytes.push(1);
            bytes.push(*value_type as u8);
            bytes.extend_from_slice(word);
        }
        Instruction::Parameter(index) => {
            bytes.push(2);
            bytes.extend_from_slice(&index.to_be_bytes());
        }
        Instruction::Local(index) => {
            bytes.push(9);
            bytes.extend_from_slice(&index.to_be_bytes());
        }
        Instruction::AddU64 => bytes.push(3),
        Instruction::SubU64 => bytes.push(4),
        Instruction::MulU64 => bytes.push(5),
        Instruction::DivU64 => bytes.push(6),
        Instruction::Eq => bytes.push(7),
        Instruction::LtU64 => bytes.push(8),
    }
}

fn decode_instruction(reader: &mut Reader<'_>, version: u8) -> Result<Instruction> {
    match reader.byte()? {
        1 => {
            let value_type = ValueType::from_byte(reader.byte()?)?;
            let mut word = [0u8; 32];
            word.copy_from_slice(reader.take(32)?);
            validate_word(value_type, &word)?;
            Ok(Instruction::Constant(value_type, word))
        }
        2 => Ok(Instruction::Parameter(reader.u16()?)),
        3 => Ok(Instruction::AddU64),
        4 => Ok(Instruction::SubU64),
        5 => Ok(Instruction::MulU64),
        6 => Ok(Instruction::DivU64),
        7 => Ok(Instruction::Eq),
        8 => Ok(Instruction::LtU64),
        9 if version >= VERSION => Ok(Instruction::Local(reader.u16()?)),
        opcode => bail!("unknown LithoVM instruction opcode {opcode}"),
    }
}

fn decode_expression(reader: &mut Reader<'_>, version: u8) -> Result<Vec<Instruction>> {
    let instruction_count = reader.u16()? as usize;
    if instruction_count == 0 || instruction_count > MAX_INSTRUCTIONS {
        bail!("invalid LithoVM instruction count {instruction_count}");
    }
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        instructions.push(decode_instruction(reader, version)?);
    }
    Ok(instructions)
}

fn decode_statements(reader: &mut Reader<'_>, version: u8, depth: usize) -> Result<Vec<Statement>> {
    if depth > MAX_BLOCK_DEPTH {
        bail!("LithoVM statement nesting exceeds {MAX_BLOCK_DEPTH}");
    }
    let statement_count = reader.u16()? as usize;
    if statement_count == 0 || statement_count > MAX_STATEMENTS {
        bail!("invalid LithoVM statement count {statement_count}");
    }
    let mut statements = Vec::with_capacity(statement_count);
    for _ in 0..statement_count {
        statements.push(match reader.byte()? {
            1 => Statement::Let {
                value_type: ValueType::from_byte(reader.byte()?)?,
                expression: decode_expression(reader, version)?,
            },
            2 => Statement::Return(decode_expression(reader, version)?),
            3 => Statement::If {
                condition: decode_expression(reader, version)?,
                then_branch: decode_statements(reader, version, depth + 1)?,
                else_branch: decode_statements(reader, version, depth + 1)?,
            },
            opcode => bail!("unknown LithoVM statement opcode {opcode}"),
        });
    }
    Ok(statements)
}

fn validate_expression(
    instructions: &[Instruction],
    parameters: &[ValueType],
    locals: &[ValueType],
    return_type: ValueType,
) -> Result<()> {
    if instructions.is_empty() || instructions.len() > MAX_INSTRUCTIONS {
        bail!("expression instruction count is outside the supported range");
    }
    let mut stack = Vec::new();
    for instruction in instructions {
        match instruction {
            Instruction::Constant(value_type, word) => {
                validate_word(*value_type, word)?;
                stack.push(*value_type);
            }
            Instruction::Parameter(index) => stack.push(
                *parameters
                    .get(*index as usize)
                    .ok_or_else(|| anyhow!("expression parameter index {index} is out of range"))?,
            ),
            Instruction::Local(index) => stack.push(
                *locals
                    .get(*index as usize)
                    .ok_or_else(|| anyhow!("expression local index {index} is out of range"))?,
            ),
            Instruction::AddU64
            | Instruction::SubU64
            | Instruction::MulU64
            | Instruction::DivU64 => {
                pop_expected(&mut stack, ValueType::U64)?;
                pop_expected(&mut stack, ValueType::U64)?;
                stack.push(ValueType::U64);
            }
            Instruction::Eq => {
                let right = stack
                    .pop()
                    .ok_or_else(|| anyhow!("expression stack underflow"))?;
                let left = stack
                    .pop()
                    .ok_or_else(|| anyhow!("expression stack underflow"))?;
                if left != right {
                    bail!("equality operands have different types");
                }
                stack.push(ValueType::Bool);
            }
            Instruction::LtU64 => {
                pop_expected(&mut stack, ValueType::U64)?;
                pop_expected(&mut stack, ValueType::U64)?;
                stack.push(ValueType::Bool);
            }
        }
    }
    if stack.as_slice() != [return_type] {
        bail!("expression must leave exactly one value matching the function return type");
    }
    Ok(())
}

fn validate_statements(
    statements: &[Statement],
    parameters: &[ValueType],
    return_type: ValueType,
    inherited_locals: &[ValueType],
    depth: usize,
) -> Result<()> {
    if depth > MAX_BLOCK_DEPTH {
        bail!("LithoVM statement nesting exceeds {MAX_BLOCK_DEPTH}");
    }
    if statements.is_empty() || statements.len() > MAX_STATEMENTS {
        bail!("statement block size is outside the supported range");
    }
    let mut locals = inherited_locals.to_vec();
    let mut terminal = false;
    for statement in statements {
        if terminal {
            bail!("unreachable statement after terminal return or branch");
        }
        match statement {
            Statement::Let {
                value_type,
                expression,
            } => {
                validate_expression(expression, parameters, &locals, *value_type)?;
                if locals.len() >= MAX_LOCALS {
                    bail!("function exceeds {MAX_LOCALS} local bindings");
                }
                locals.push(*value_type);
            }
            Statement::Return(expression) => {
                validate_expression(expression, parameters, &locals, return_type)?;
                terminal = true;
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
            } => {
                validate_expression(condition, parameters, &locals, ValueType::Bool)?;
                validate_statements(then_branch, parameters, return_type, &locals, depth + 1)?;
                validate_statements(else_branch, parameters, return_type, &locals, depth + 1)?;
                terminal = true;
            }
        }
    }
    if !terminal {
        bail!("statement block does not return on every path");
    }
    Ok(())
}

fn pop_expected(stack: &mut Vec<ValueType>, expected: ValueType) -> Result<()> {
    let actual = stack
        .pop()
        .ok_or_else(|| anyhow!("expression stack underflow"))?;
    if actual != expected {
        bail!(
            "expression expected {}, found {}",
            expected.name(),
            actual.name()
        );
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn push_u16(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u16::try_from(value).map_err(|_| anyhow!("value exceeds u16 encoding"))?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| anyhow!("bytecode offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| anyhow!("truncated LithoVM bytecode"))?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Program {
        Program {
            functions: vec![Function {
                name: "answer".into(),
                parameters: vec![],
                return_type: ValueType::U64,
                return_value: ReturnValue::Constant({
                    let mut word = [0u8; 32];
                    word[31] = 42;
                    word
                }),
            }],
        }
    }

    #[test]
    fn versioned_program_round_trips_deterministically() {
        let program = sample();
        let first = program.encode().unwrap();
        assert_eq!(first, program.encode().unwrap());
        assert_eq!(parse(&first).unwrap(), program);
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_unknown_versions() {
        let bytes = sample().encode().unwrap();
        for length in 0..bytes.len() {
            assert!(parse(&bytes[..length]).is_err(), "accepted length {length}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
        let mut version = bytes;
        version[MAGIC.len()] = VERSION + 1;
        assert!(parse(&version).is_err());
    }

    #[test]
    fn rejects_non_canonical_constant_words() {
        let mut program = sample();
        program.functions[0].return_value = ReturnValue::Constant([0xff; 32]);
        assert!(program.encode().is_err());
    }

    #[test]
    fn typed_expression_round_trips_and_rejects_bad_stacks() {
        let program = Program {
            functions: vec![Function {
                name: "add".into(),
                parameters: vec![ValueType::U64],
                return_type: ValueType::U64,
                return_value: ReturnValue::Expression(vec![
                    Instruction::Parameter(0),
                    Instruction::Constant(ValueType::U64, {
                        let mut word = [0; 32];
                        word[31] = 1;
                        word
                    }),
                    Instruction::AddU64,
                ]),
            }],
        };
        let bytes = program.encode().unwrap();
        assert_eq!(parse(&bytes).unwrap(), program);

        let mut invalid = program;
        invalid.functions[0].return_value = ReturnValue::Expression(vec![Instruction::AddU64]);
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn structured_statements_round_trip_and_validate_local_types() {
        let program = Program {
            functions: vec![Function {
                name: "choose".into(),
                parameters: vec![ValueType::U64, ValueType::Bool],
                return_type: ValueType::U64,
                return_value: ReturnValue::Statements(vec![
                    Statement::Let {
                        value_type: ValueType::U64,
                        expression: vec![Instruction::Parameter(0)],
                    },
                    Statement::If {
                        condition: vec![Instruction::Parameter(1)],
                        then_branch: vec![Statement::Return(vec![Instruction::Local(0)])],
                        else_branch: vec![Statement::Return(vec![Instruction::Constant(
                            ValueType::U64,
                            {
                                let mut word = [0; 32];
                                word[31] = 9;
                                word
                            },
                        )])],
                    },
                ]),
            }],
        };
        let bytes = program.encode().unwrap();
        assert_eq!(bytes[MAGIC.len()], VERSION);
        assert_eq!(parse(&bytes).unwrap(), program);

        let mut invalid = program;
        let ReturnValue::Statements(statements) = &mut invalid.functions[0].return_value else {
            unreachable!()
        };
        let Statement::If { then_branch, .. } = &mut statements[1] else {
            unreachable!()
        };
        *then_branch = vec![Statement::Return(vec![Instruction::Local(1)])];
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn legacy_v1_artifacts_remain_readable() {
        let mut bytes = sample().encode().unwrap();
        bytes[MAGIC.len()] = LEGACY_VERSION;
        assert_eq!(parse(&bytes).unwrap(), sample());
    }
}
