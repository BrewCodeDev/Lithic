use anyhow::{anyhow, bail, Result};

pub const MAGIC: &[u8; 7] = b"LITHOVM";
pub const LEGACY_VERSION: u8 = 1;
pub const STATEMENT_VERSION: u8 = 2;
pub const STORAGE_VERSION: u8 = 3;
pub const CONTEXT_VERSION: u8 = 4;
pub const EVENT_VERSION: u8 = 5;
pub const TRANSFER_VERSION: u8 = 6;
pub const VERSION: u8 = 7;
pub const MAX_FUNCTIONS: usize = 1024;
pub const MAX_PARAMETERS: usize = 64;
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_LOCALS: usize = 256;
pub const MAX_STATEMENTS: usize = 4096;
pub const MAX_BLOCK_DEPTH: usize = 64;
pub const MAX_STORAGE_FIELDS: usize = 256;
pub const MAX_EVENTS: usize = 256;
pub const MAX_EVENT_FIELDS: usize = 64;

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
    Store {
        field: u16,
        expression: Vec<Instruction>,
    },
    Emit {
        event: u16,
        values: Vec<Vec<Instruction>>,
    },
    Transfer {
        recipient: Vec<Instruction>,
        amount: Vec<Instruction>,
    },
    Call {
        target: Vec<Instruction>,
        selector: Vec<Instruction>,
        value: Vec<Instruction>,
    },
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
    Storage(u16),
    MessageSender,
    MessageValue,
    BlockHeight,
    BlockTimestamp,
    ChainId,
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
pub struct StorageField {
    pub name: String,
    pub value_type: ValueType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDefinition {
    pub name: String,
    pub fields: Vec<StorageField>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub storage: Vec<StorageField>,
    pub events: Vec<EventDefinition>,
    pub functions: Vec<Function>,
}

impl Program {
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_storage(&self.storage)?;
        validate_events(&self.events)?;
        validate_functions(&self.functions, &self.storage, &self.events)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        push_u16(&mut bytes, self.storage.len())?;
        for field in &self.storage {
            push_u16(&mut bytes, field.name.len())?;
            bytes.extend_from_slice(field.name.as_bytes());
            bytes.push(field.value_type as u8);
        }
        push_u16(&mut bytes, self.events.len())?;
        for event in &self.events {
            push_name(&mut bytes, &event.name)?;
            push_u16(&mut bytes, event.fields.len())?;
            for field in &event.fields {
                push_name(&mut bytes, &field.name)?;
                bytes.push(field.value_type as u8);
            }
        }
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
    if !(LEGACY_VERSION..=VERSION).contains(&version) {
        bail!("unsupported LithoVM bytecode version {version}");
    }
    let storage = if version >= STORAGE_VERSION {
        let field_count = reader.u16()? as usize;
        if field_count > MAX_STORAGE_FIELDS {
            bail!("too many LithoVM storage fields: {field_count}");
        }
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            let name_len = reader.u16()? as usize;
            if name_len == 0 || name_len > MAX_NAME_BYTES {
                bail!("invalid LithoVM storage field name length {name_len}");
            }
            let name = std::str::from_utf8(reader.take(name_len)?)
                .map_err(|_| anyhow!("storage field name is not valid UTF-8"))?
                .to_owned();
            let value_type = ValueType::from_byte(reader.byte()?)?;
            fields.push(StorageField { name, value_type });
        }
        validate_storage(&fields)?;
        fields
    } else {
        Vec::new()
    };
    let events = if version >= EVENT_VERSION {
        let event_count = reader.u16()? as usize;
        if event_count > MAX_EVENTS {
            bail!("too many LithoVM events: {event_count}");
        }
        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            let name = read_name(&mut reader, "event")?;
            let field_count = reader.u16()? as usize;
            if field_count > MAX_EVENT_FIELDS {
                bail!("too many fields in LithoVM event '{name}'");
            }
            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                fields.push(StorageField {
                    name: read_name(&mut reader, "event field")?,
                    value_type: ValueType::from_byte(reader.byte()?)?,
                });
            }
            events.push(EventDefinition { name, fields });
        }
        validate_events(&events)?;
        events
    } else {
        Vec::new()
    };
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
                validate_expression(&instructions, &parameters, &[], &storage, return_type)?;
                ReturnValue::Expression(instructions)
            }
            4 if version >= STATEMENT_VERSION => {
                let statements = decode_statements(&mut reader, version, 0)?;
                validate_statements(
                    &statements,
                    &parameters,
                    return_type,
                    &[],
                    &storage,
                    &events,
                    0,
                )?;
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
    validate_functions(&functions, &storage, &events)?;
    Ok(Program {
        storage,
        events,
        functions,
    })
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

fn validate_storage(storage: &[StorageField]) -> Result<()> {
    if storage.len() > MAX_STORAGE_FIELDS {
        bail!("program exceeds {MAX_STORAGE_FIELDS} storage fields");
    }
    for (index, field) in storage.iter().enumerate() {
        if field.name.is_empty()
            || field.name.len() > MAX_NAME_BYTES
            || !field.name.is_ascii()
            || !is_identifier(&field.name)
        {
            bail!("invalid LithoVM storage field name '{}'", field.name);
        }
        if storage[..index]
            .iter()
            .any(|earlier| earlier.name == field.name)
        {
            bail!("duplicate LithoVM storage field name '{}'", field.name);
        }
    }
    Ok(())
}

fn validate_events(events: &[EventDefinition]) -> Result<()> {
    if events.len() > MAX_EVENTS {
        bail!("program exceeds {MAX_EVENTS} events");
    }
    for (index, event) in events.iter().enumerate() {
        validate_name(&event.name, "event")?;
        if events[..index]
            .iter()
            .any(|earlier| earlier.name == event.name)
        {
            bail!("duplicate LithoVM event name '{}'", event.name);
        }
        if event.fields.len() > MAX_EVENT_FIELDS {
            bail!("event '{}' exceeds {MAX_EVENT_FIELDS} fields", event.name);
        }
        for (field_index, field) in event.fields.iter().enumerate() {
            validate_name(&field.name, "event field")?;
            if event.fields[..field_index]
                .iter()
                .any(|earlier| earlier.name == field.name)
            {
                bail!("duplicate field '{}' in event '{}'", field.name, event.name);
            }
        }
    }
    Ok(())
}

fn validate_functions(
    functions: &[Function],
    storage: &[StorageField],
    events: &[EventDefinition],
) -> Result<()> {
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
                    storage,
                    function.return_type,
                )?;
            }
            ReturnValue::Statements(ref statements) => {
                validate_statements(
                    statements,
                    &function.parameters,
                    function.return_type,
                    &[],
                    storage,
                    events,
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
            Statement::Store { field, expression } => {
                bytes.push(4);
                bytes.extend_from_slice(&field.to_be_bytes());
                encode_expression(bytes, expression)?;
            }
            Statement::Emit { event, values } => {
                bytes.push(5);
                bytes.extend_from_slice(&event.to_be_bytes());
                push_u16(bytes, values.len())?;
                for value in values {
                    encode_expression(bytes, value)?;
                }
            }
            Statement::Transfer { recipient, amount } => {
                bytes.push(6);
                encode_expression(bytes, recipient)?;
                encode_expression(bytes, amount)?;
            }
            Statement::Call {
                target,
                selector,
                value,
            } => {
                bytes.push(7);
                encode_expression(bytes, target)?;
                encode_expression(bytes, selector)?;
                encode_expression(bytes, value)?;
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
        Instruction::Storage(index) => {
            bytes.push(10);
            bytes.extend_from_slice(&index.to_be_bytes());
        }
        Instruction::MessageSender => bytes.push(11),
        Instruction::MessageValue => bytes.push(12),
        Instruction::BlockHeight => bytes.push(13),
        Instruction::BlockTimestamp => bytes.push(14),
        Instruction::ChainId => bytes.push(15),
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
        9 if version >= STATEMENT_VERSION => Ok(Instruction::Local(reader.u16()?)),
        10 if version >= STORAGE_VERSION => Ok(Instruction::Storage(reader.u16()?)),
        11 if version >= CONTEXT_VERSION => Ok(Instruction::MessageSender),
        12 if version >= CONTEXT_VERSION => Ok(Instruction::MessageValue),
        13 if version >= CONTEXT_VERSION => Ok(Instruction::BlockHeight),
        14 if version >= CONTEXT_VERSION => Ok(Instruction::BlockTimestamp),
        15 if version >= CONTEXT_VERSION => Ok(Instruction::ChainId),
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
            4 if version >= STORAGE_VERSION => Statement::Store {
                field: reader.u16()?,
                expression: decode_expression(reader, version)?,
            },
            5 if version >= EVENT_VERSION => {
                let event = reader.u16()?;
                let count = reader.u16()? as usize;
                if count > MAX_EVENT_FIELDS {
                    bail!("event emission exceeds {MAX_EVENT_FIELDS} values");
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(decode_expression(reader, version)?);
                }
                Statement::Emit { event, values }
            }
            6 if version >= TRANSFER_VERSION => Statement::Transfer {
                recipient: decode_expression(reader, version)?,
                amount: decode_expression(reader, version)?,
            },
            7 if version >= VERSION => Statement::Call {
                target: decode_expression(reader, version)?,
                selector: decode_expression(reader, version)?,
                value: decode_expression(reader, version)?,
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
    storage: &[StorageField],
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
            Instruction::Storage(index) => stack.push(
                storage
                    .get(*index as usize)
                    .ok_or_else(|| anyhow!("expression storage index {index} is out of range"))?
                    .value_type,
            ),
            Instruction::MessageSender => stack.push(ValueType::Address),
            Instruction::MessageValue => stack.push(ValueType::U256),
            Instruction::BlockHeight | Instruction::BlockTimestamp | Instruction::ChainId => {
                stack.push(ValueType::U64)
            }
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
    storage: &[StorageField],
    events: &[EventDefinition],
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
                validate_expression(expression, parameters, &locals, storage, *value_type)?;
                if locals.len() >= MAX_LOCALS {
                    bail!("function exceeds {MAX_LOCALS} local bindings");
                }
                locals.push(*value_type);
            }
            Statement::Return(expression) => {
                validate_expression(expression, parameters, &locals, storage, return_type)?;
                terminal = true;
            }
            Statement::Store { field, expression } => {
                let value_type = storage
                    .get(*field as usize)
                    .ok_or_else(|| anyhow!("store field index {field} is out of range"))?
                    .value_type;
                validate_expression(expression, parameters, &locals, storage, value_type)?;
            }
            Statement::Emit { event, values } => {
                let definition = events
                    .get(*event as usize)
                    .ok_or_else(|| anyhow!("event index {event} is out of range"))?;
                if values.len() != definition.fields.len() {
                    bail!(
                        "event '{}' value count does not match schema",
                        definition.name
                    );
                }
                for (value, field) in values.iter().zip(&definition.fields) {
                    validate_expression(value, parameters, &locals, storage, field.value_type)?;
                }
            }
            Statement::Transfer { recipient, amount } => {
                validate_expression(recipient, parameters, &locals, storage, ValueType::Address)?;
                validate_expression(amount, parameters, &locals, storage, ValueType::U256)?;
            }
            Statement::Call {
                target,
                selector,
                value,
            } => {
                validate_expression(target, parameters, &locals, storage, ValueType::Address)?;
                validate_expression(selector, parameters, &locals, storage, ValueType::Bytes32)?;
                validate_expression(value, parameters, &locals, storage, ValueType::U256)?;
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
            } => {
                validate_expression(condition, parameters, &locals, storage, ValueType::Bool)?;
                validate_statements(
                    then_branch,
                    parameters,
                    return_type,
                    &locals,
                    storage,
                    events,
                    depth + 1,
                )?;
                validate_statements(
                    else_branch,
                    parameters,
                    return_type,
                    &locals,
                    storage,
                    events,
                    depth + 1,
                )?;
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

fn validate_name(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || !value.is_ascii()
        || !is_identifier(value)
    {
        bail!("invalid LithoVM {kind} name '{value}'");
    }
    Ok(())
}

fn push_name(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    push_u16(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_name(reader: &mut Reader<'_>, kind: &str) -> Result<String> {
    let length = reader.u16()? as usize;
    if length == 0 || length > MAX_NAME_BYTES {
        bail!("invalid LithoVM {kind} name length {length}");
    }
    let value = std::str::from_utf8(reader.take(length)?)
        .map_err(|_| anyhow!("{kind} name is not valid UTF-8"))?
        .to_owned();
    validate_name(&value, kind)?;
    Ok(value)
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
            storage: vec![],
            events: vec![],
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

    fn strip_empty_event_table(mut bytes: Vec<u8>, storage: &[StorageField]) -> Vec<u8> {
        let mut offset = MAGIC.len() + 1 + 2;
        for field in storage {
            offset += 2 + field.name.len() + 1;
        }
        assert_eq!(&bytes[offset..offset + 2], &[0, 0]);
        bytes.drain(offset..offset + 2);
        bytes
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
            storage: vec![],
            events: vec![],
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
        let mut v3 = strip_empty_event_table(bytes.clone(), &program.storage);
        v3[MAGIC.len()] = STORAGE_VERSION;
        assert_eq!(parse(&v3).unwrap(), program);

        let mut invalid = program;
        invalid.functions[0].return_value = ReturnValue::Expression(vec![Instruction::AddU64]);
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn structured_statements_round_trip_and_validate_local_types() {
        let program = Program {
            storage: vec![],
            events: vec![],
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
    fn older_artifact_versions_remain_readable() {
        for version in [LEGACY_VERSION, STATEMENT_VERSION] {
            let mut bytes = sample().encode().unwrap();
            bytes[MAGIC.len()] = version;
            bytes.drain(MAGIC.len() + 1..MAGIC.len() + 5);
            assert_eq!(parse(&bytes).unwrap(), sample());
        }

        for version in [STORAGE_VERSION, CONTEXT_VERSION] {
            let mut bytes = strip_empty_event_table(sample().encode().unwrap(), &[]);
            bytes[MAGIC.len()] = version;
            assert_eq!(parse(&bytes).unwrap(), sample());
        }
        let mut v5 = sample().encode().unwrap();
        v5[MAGIC.len()] = EVENT_VERSION;
        assert_eq!(parse(&v5).unwrap(), sample());
        let mut v6 = sample().encode().unwrap();
        v6[MAGIC.len()] = TRANSFER_VERSION;
        assert_eq!(parse(&v6).unwrap(), sample());
    }

    #[test]
    fn storage_schema_reads_and_writes_round_trip() {
        let program = Program {
            storage: vec![StorageField {
                name: "count".into(),
                value_type: ValueType::U64,
            }],
            events: vec![],
            functions: vec![Function {
                name: "set".into(),
                parameters: vec![ValueType::U64],
                return_type: ValueType::U64,
                return_value: ReturnValue::Statements(vec![
                    Statement::Store {
                        field: 0,
                        expression: vec![Instruction::Parameter(0)],
                    },
                    Statement::Return(vec![Instruction::Storage(0)]),
                ]),
            }],
        };
        let bytes = program.encode().unwrap();
        assert_eq!(parse(&bytes).unwrap(), program);
        let mut storage_v3 = strip_empty_event_table(bytes.clone(), &program.storage);
        storage_v3[MAGIC.len()] = STORAGE_VERSION;
        assert_eq!(parse(&storage_v3).unwrap(), program);

        let mut invalid = program;
        invalid.functions[0].return_value = ReturnValue::Statements(vec![
            Statement::Store {
                field: 1,
                expression: vec![Instruction::Parameter(0)],
            },
            Statement::Return(vec![Instruction::Storage(0)]),
        ]);
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn execution_context_instructions_round_trip_with_static_types() {
        for (instruction, return_type) in [
            (Instruction::MessageSender, ValueType::Address),
            (Instruction::MessageValue, ValueType::U256),
            (Instruction::BlockHeight, ValueType::U64),
            (Instruction::BlockTimestamp, ValueType::U64),
            (Instruction::ChainId, ValueType::U64),
        ] {
            let program = Program {
                storage: vec![],
                events: vec![],
                functions: vec![Function {
                    name: "context".into(),
                    parameters: vec![],
                    return_type,
                    return_value: ReturnValue::Expression(vec![instruction]),
                }],
            };
            let bytes = program.encode().unwrap();
            assert_eq!(parse(&bytes).unwrap(), program);
            let mut mislabeled_v3 = strip_empty_event_table(bytes, &[]);
            mislabeled_v3[MAGIC.len()] = STORAGE_VERSION;
            assert!(parse(&mislabeled_v3).is_err());
        }
    }

    #[test]
    fn typed_event_schema_and_emission_round_trip() {
        let program = Program {
            storage: vec![],
            events: vec![EventDefinition {
                name: "Changed".into(),
                fields: vec![StorageField {
                    name: "value".into(),
                    value_type: ValueType::U64,
                }],
            }],
            functions: vec![Function {
                name: "change".into(),
                parameters: vec![ValueType::U64],
                return_type: ValueType::U64,
                return_value: ReturnValue::Statements(vec![
                    Statement::Emit {
                        event: 0,
                        values: vec![vec![Instruction::Parameter(0)]],
                    },
                    Statement::Return(vec![Instruction::Parameter(0)]),
                ]),
            }],
        };
        let bytes = program.encode().unwrap();
        assert_eq!(parse(&bytes).unwrap(), program);

        let mut invalid = program;
        invalid.functions[0].return_value = ReturnValue::Statements(vec![
            Statement::Emit {
                event: 1,
                values: vec![vec![Instruction::Parameter(0)]],
            },
            Statement::Return(vec![Instruction::Parameter(0)]),
        ]);
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn native_transfer_statement_round_trips_with_static_types() {
        let program = Program {
            storage: vec![],
            events: vec![],
            functions: vec![Function {
                name: "pay".into(),
                parameters: vec![ValueType::Address, ValueType::U256],
                return_type: ValueType::U256,
                return_value: ReturnValue::Statements(vec![
                    Statement::Transfer {
                        recipient: vec![Instruction::Parameter(0)],
                        amount: vec![Instruction::Parameter(1)],
                    },
                    Statement::Return(vec![Instruction::Parameter(1)]),
                ]),
            }],
        };
        let bytes = program.encode().unwrap();
        assert_eq!(parse(&bytes).unwrap(), program);
        let mut mislabeled_v5 = bytes;
        mislabeled_v5[MAGIC.len()] = EVENT_VERSION;
        assert!(parse(&mislabeled_v5).is_err());
    }

    #[test]
    fn contract_call_statement_round_trips_with_static_types() {
        let program = Program {
            storage: vec![],
            events: vec![],
            functions: vec![Function {
                name: "invoke".into(),
                parameters: vec![ValueType::Address, ValueType::Bytes32, ValueType::U256],
                return_type: ValueType::U256,
                return_value: ReturnValue::Statements(vec![
                    Statement::Call {
                        target: vec![Instruction::Parameter(0)],
                        selector: vec![Instruction::Parameter(1)],
                        value: vec![Instruction::Parameter(2)],
                    },
                    Statement::Return(vec![Instruction::Parameter(2)]),
                ]),
            }],
        };
        let bytes = program.encode().unwrap();
        assert_eq!(parse(&bytes).unwrap(), program);
        let mut mislabeled_v6 = bytes;
        mislabeled_v6[MAGIC.len()] = TRANSFER_VERSION;
        assert!(parse(&mislabeled_v6).is_err());
    }
}
