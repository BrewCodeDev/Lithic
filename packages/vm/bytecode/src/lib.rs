use anyhow::{anyhow, bail, Result};

pub const MAGIC: &[u8; 7] = b"LITHOVM";
pub const VERSION: u8 = 1;
pub const MAX_FUNCTIONS: usize = 1024;
pub const MAX_PARAMETERS: usize = 64;
pub const MAX_NAME_BYTES: usize = 255;

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
    if version != VERSION {
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
        }
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
}
