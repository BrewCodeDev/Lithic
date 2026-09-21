use anyhow::{anyhow, bail, Result};
use lithovm_bytecode::{
    parse, validate_word, Instruction, Program, ReturnValue, Statement, ValueType,
};
use lithovm_receipts::ReceiptV1;
use lithovm_zk_verifier::{StubVerifier, ZkVerifier};
use std::collections::BTreeMap;

/// Minimal LithoVM execution context (scaffold).
pub struct Vm {
    verifier: Box<dyn ZkVerifier + Send + Sync>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub return_type: ValueType,
    pub return_value: [u8; 32],
    pub gas_used: u64,
    pub events: Vec<EventRecord>,
    pub transfers: Vec<NativeTransfer>,
    pub calls: Vec<ContractCall>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub name: String,
    pub fields: Vec<(String, ValueType, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTransfer {
    pub recipient: [u8; 32],
    pub amount: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCall {
    pub target: [u8; 32],
    pub selector: [u8; 32],
    pub value: [u8; 32],
    pub depth: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionContext {
    pub caller: [u8; 32],
    pub value: [u8; 32],
    pub block_height: u64,
    pub block_timestamp: u64,
    pub chain_id: u64,
    pub contract_balance: [u8; 32],
    pub call_depth: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Storage {
    values: BTreeMap<String, [u8; 32]>,
}

impl Storage {
    pub fn get(&self, field: &str) -> Option<&[u8; 32]> {
        self.values.get(field)
    }

    pub fn set_word(&mut self, field: impl Into<String>, word: [u8; 32]) {
        self.values.insert(field.into(), word);
    }
}

pub const BASE_CALL_GAS: u64 = 10;
pub const PARAMETER_GAS: u64 = 2;
pub const INSTRUCTION_GAS: u64 = 1;
pub const NATIVE_TRANSFER_GAS: u64 = 20;
pub const CONTRACT_CALL_GAS: u64 = 40;
pub const MAX_CALL_DEPTH: u16 = 32;

impl Default for Vm {
    fn default() -> Self {
        Self {
            verifier: Box::new(StubVerifier),
        }
    }
}

impl Vm {
    pub fn load_and_validate(&self, bytes: &[u8]) -> Result<()> {
        let _bc = parse(bytes)?;
        Ok(())
    }

    pub fn execute(
        &self,
        bytes: &[u8],
        function_name: &str,
        arguments: &[[u8; 32]],
        gas_limit: u64,
    ) -> Result<ExecutionResult> {
        let program = parse(bytes)?;
        if !program.storage.is_empty() {
            bail!("stateful LithoVM program requires execute_with_storage");
        }
        let mut storage = Storage::default();
        execute_program(
            &program,
            function_name,
            arguments,
            gas_limit,
            &mut storage,
            None,
        )
    }

    pub fn execute_with_context(
        &self,
        bytes: &[u8],
        function_name: &str,
        arguments: &[[u8; 32]],
        gas_limit: u64,
        context: &ExecutionContext,
    ) -> Result<ExecutionResult> {
        let program = parse(bytes)?;
        if !program.storage.is_empty() {
            bail!("stateful LithoVM program requires execute_with_storage_and_context");
        }
        validate_context(context)?;
        let mut storage = Storage::default();
        execute_program(
            &program,
            function_name,
            arguments,
            gas_limit,
            &mut storage,
            Some(context),
        )
    }

    pub fn execute_with_storage(
        &self,
        bytes: &[u8],
        function_name: &str,
        arguments: &[[u8; 32]],
        gas_limit: u64,
        storage: &mut Storage,
    ) -> Result<ExecutionResult> {
        let program = parse(bytes)?;
        let mut staged = storage.clone();
        prepare_storage(&program, &mut staged)?;
        let result = execute_program(
            &program,
            function_name,
            arguments,
            gas_limit,
            &mut staged,
            None,
        )?;
        *storage = staged;
        Ok(result)
    }

    pub fn execute_with_storage_and_context(
        &self,
        bytes: &[u8],
        function_name: &str,
        arguments: &[[u8; 32]],
        gas_limit: u64,
        storage: &mut Storage,
        context: &ExecutionContext,
    ) -> Result<ExecutionResult> {
        let program = parse(bytes)?;
        validate_context(context)?;
        let mut staged = storage.clone();
        prepare_storage(&program, &mut staged)?;
        let result = execute_program(
            &program,
            function_name,
            arguments,
            gas_limit,
            &mut staged,
            Some(context),
        )?;
        *storage = staged;
        Ok(result)
    }

    /// Validate a receipt signature/zk-proof at a high level (scaffold).
    /// Production: enforce LEP100-2/4/5 rules in consensus + runtime.
    pub fn validate_receipt(&self, _receipt: &ReceiptV1) -> Result<()> {
        Ok(())
    }

    pub fn verify_zk(
        &self,
        proof_system: &str,
        vk_id: &[u8],
        public_inputs: &[u8],
        proof: &[u8],
    ) -> Result<bool> {
        self.verifier
            .verify(proof_system, vk_id, public_inputs, proof)
    }
}

fn execute_program(
    program: &Program,
    function_name: &str,
    arguments: &[[u8; 32]],
    gas_limit: u64,
    storage: &mut Storage,
    context: Option<&ExecutionContext>,
) -> Result<ExecutionResult> {
    let function = program
        .functions
        .iter()
        .find(|function| function.name == function_name)
        .ok_or_else(|| anyhow!("unknown LithoVM function '{function_name}'"))?;
    if function.parameters.len() != arguments.len() {
        bail!(
            "function '{}' requires {} arguments, received {}",
            function.name,
            function.parameters.len(),
            arguments.len()
        );
    }
    for (index, (value_type, word)) in function.parameters.iter().zip(arguments).enumerate() {
        validate_word(*value_type, word).map_err(|error| anyhow!("argument {index}: {error}"))?;
    }
    let instruction_count = match &function.return_value {
        ReturnValue::Expression(instructions) => instructions.len() as u64,
        ReturnValue::Statements(_) => 0,
        _ => 0,
    };
    let gas_used = BASE_CALL_GAS
        .checked_add(PARAMETER_GAS.saturating_mul(arguments.len() as u64))
        .and_then(|gas| gas.checked_add(INSTRUCTION_GAS.saturating_mul(instruction_count)))
        .ok_or_else(|| anyhow!("gas calculation overflow"))?;
    if gas_limit < gas_used {
        bail!("out of gas: requires {gas_used}, limit is {gas_limit}");
    }
    let mut environment = RuntimeEnvironment {
        storage_fields: &program.storage,
        event_definitions: &program.events,
        storage,
        context,
        events: Vec::new(),
        transfers: Vec::new(),
        calls: Vec::new(),
        remaining_balance: context.map_or([0; 32], |value| value.contract_balance),
    };
    let return_value = match &function.return_value {
        ReturnValue::Constant(word) => word,
        ReturnValue::Parameter(index) => &arguments[*index as usize],
        ReturnValue::Expression(instructions) => {
            return execute_expression(
                instructions,
                arguments,
                &function.parameters,
                function.return_type,
                gas_used,
                &environment,
            )
        }
        ReturnValue::Statements(statements) => {
            return execute_statements(
                statements,
                arguments,
                &function.parameters,
                function.return_type,
                gas_used,
                gas_limit,
                &mut environment,
            )
        }
    };
    Ok(ExecutionResult {
        return_type: function.return_type,
        return_value: *return_value,
        gas_used,
        events: environment.events,
        transfers: environment.transfers,
        calls: environment.calls,
    })
}

fn validate_context(context: &ExecutionContext) -> Result<()> {
    validate_word(ValueType::Address, &context.caller)
        .map_err(|error| anyhow!("execution context caller: {error}"))?;
    validate_word(ValueType::U256, &context.value)
        .map_err(|error| anyhow!("execution context value: {error}"))?;
    validate_word(ValueType::U256, &context.contract_balance)
        .map_err(|error| anyhow!("execution context contract balance: {error}"))?;
    if context.call_depth > MAX_CALL_DEPTH {
        bail!("execution context call depth exceeds {MAX_CALL_DEPTH}");
    }
    Ok(())
}

fn prepare_storage(program: &Program, storage: &mut Storage) -> Result<()> {
    for name in storage.values.keys() {
        if !program.storage.iter().any(|field| field.name == *name) {
            bail!("storage contains unknown field '{name}'");
        }
    }
    for field in &program.storage {
        let word = storage.values.entry(field.name.clone()).or_insert([0; 32]);
        validate_word(field.value_type, word)
            .map_err(|error| anyhow!("storage field '{}': {error}", field.name))?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct StackValue {
    value_type: ValueType,
    word: [u8; 32],
}

struct RuntimeEnvironment<'a> {
    storage_fields: &'a [lithovm_bytecode::StorageField],
    event_definitions: &'a [lithovm_bytecode::EventDefinition],
    storage: &'a mut Storage,
    context: Option<&'a ExecutionContext>,
    events: Vec<EventRecord>,
    transfers: Vec<NativeTransfer>,
    calls: Vec<ContractCall>,
    remaining_balance: [u8; 32],
}

fn execute_expression(
    instructions: &[Instruction],
    arguments: &[[u8; 32]],
    parameter_types: &[ValueType],
    return_type: ValueType,
    gas_used: u64,
    environment: &RuntimeEnvironment<'_>,
) -> Result<ExecutionResult> {
    let result = evaluate_expression(instructions, arguments, parameter_types, &[], environment)?;
    validate_word(return_type, &result.word)?;
    if result.value_type != return_type {
        bail!("expression runtime type does not match function return type");
    }
    Ok(ExecutionResult {
        return_type,
        return_value: result.word,
        gas_used,
        events: Vec::new(),
        transfers: Vec::new(),
        calls: Vec::new(),
    })
}

fn evaluate_expression(
    instructions: &[Instruction],
    arguments: &[[u8; 32]],
    parameter_types: &[ValueType],
    locals: &[StackValue],
    environment: &RuntimeEnvironment<'_>,
) -> Result<StackValue> {
    let mut stack: Vec<StackValue> = Vec::new();
    for instruction in instructions {
        match instruction {
            Instruction::Constant(value_type, word) => stack.push(StackValue {
                value_type: *value_type,
                word: *word,
            }),
            Instruction::Parameter(index) => stack.push(StackValue {
                value_type: parameter_types[*index as usize],
                word: arguments[*index as usize],
            }),
            Instruction::Local(index) => stack.push(
                *locals
                    .get(*index as usize)
                    .ok_or_else(|| anyhow!("runtime local index {index} is out of range"))?,
            ),
            Instruction::Storage(index) => {
                let field = environment
                    .storage_fields
                    .get(*index as usize)
                    .ok_or_else(|| anyhow!("runtime storage index {index} is out of range"))?;
                let word =
                    environment.storage.values.get(&field.name).ok_or_else(|| {
                        anyhow!("runtime storage field '{}' is missing", field.name)
                    })?;
                stack.push(StackValue {
                    value_type: field.value_type,
                    word: *word,
                });
            }
            Instruction::MessageSender => {
                let context = environment
                    .context
                    .ok_or_else(|| anyhow!("contextual program requires an execution context"))?;
                stack.push(StackValue {
                    value_type: ValueType::Address,
                    word: context.caller,
                });
            }
            Instruction::MessageValue => {
                let context = environment
                    .context
                    .ok_or_else(|| anyhow!("contextual program requires an execution context"))?;
                stack.push(StackValue {
                    value_type: ValueType::U256,
                    word: context.value,
                });
            }
            Instruction::BlockHeight => {
                let context = environment
                    .context
                    .ok_or_else(|| anyhow!("contextual program requires an execution context"))?;
                stack.push(StackValue {
                    value_type: ValueType::U64,
                    word: word_from_u64(context.block_height),
                });
            }
            Instruction::BlockTimestamp => {
                let context = environment
                    .context
                    .ok_or_else(|| anyhow!("contextual program requires an execution context"))?;
                stack.push(StackValue {
                    value_type: ValueType::U64,
                    word: word_from_u64(context.block_timestamp),
                });
            }
            Instruction::ChainId => {
                let context = environment
                    .context
                    .ok_or_else(|| anyhow!("contextual program requires an execution context"))?;
                stack.push(StackValue {
                    value_type: ValueType::U64,
                    word: word_from_u64(context.chain_id),
                });
            }
            Instruction::AddU64 => {
                binary_u64(&mut stack, u64::checked_add, "u64 addition overflow")?
            }
            Instruction::SubU64 => {
                binary_u64(&mut stack, u64::checked_sub, "u64 subtraction underflow")?
            }
            Instruction::MulU64 => {
                binary_u64(&mut stack, u64::checked_mul, "u64 multiplication overflow")?
            }
            Instruction::DivU64 => binary_u64(&mut stack, checked_div, "division by zero")?,
            Instruction::Eq => {
                let right = stack
                    .pop()
                    .ok_or_else(|| anyhow!("expression stack underflow"))?;
                let left = stack
                    .pop()
                    .ok_or_else(|| anyhow!("expression stack underflow"))?;
                if left.value_type != right.value_type {
                    bail!("equality operands have different runtime types");
                }
                stack.push(StackValue {
                    value_type: ValueType::Bool,
                    word: word_from_bool(left.word == right.word),
                });
            }
            Instruction::LtU64 => {
                let (left, right) = pop_u64_pair(&mut stack)?;
                stack.push(StackValue {
                    value_type: ValueType::Bool,
                    word: word_from_bool(left < right),
                });
            }
        }
    }
    let result = stack
        .pop()
        .ok_or_else(|| anyhow!("expression produced no result"))?;
    if !stack.is_empty() {
        bail!("expression left extra runtime values");
    }
    Ok(result)
}

struct GasMeter {
    used: u64,
    limit: u64,
}

impl GasMeter {
    fn charge(&mut self, amount: u64) -> Result<()> {
        self.used = self
            .used
            .checked_add(amount)
            .ok_or_else(|| anyhow!("gas calculation overflow"))?;
        if self.used > self.limit {
            bail!("out of gas: used {}, limit is {}", self.used, self.limit);
        }
        Ok(())
    }
}

fn execute_statements(
    statements: &[Statement],
    arguments: &[[u8; 32]],
    parameter_types: &[ValueType],
    return_type: ValueType,
    base_gas: u64,
    gas_limit: u64,
    environment: &mut RuntimeEnvironment<'_>,
) -> Result<ExecutionResult> {
    let mut meter = GasMeter {
        used: base_gas,
        limit: gas_limit,
    };
    if meter.used > meter.limit {
        bail!(
            "out of gas: requires at least {}, limit is {}",
            meter.used,
            meter.limit
        );
    }
    let mut locals = Vec::new();
    let result = execute_block(
        statements,
        arguments,
        parameter_types,
        &mut locals,
        &mut meter,
        environment,
    )?;
    if result.value_type != return_type {
        bail!("statement return type does not match function return type");
    }
    validate_word(return_type, &result.word)?;
    Ok(ExecutionResult {
        return_type,
        return_value: result.word,
        gas_used: meter.used,
        events: std::mem::take(&mut environment.events),
        transfers: std::mem::take(&mut environment.transfers),
        calls: std::mem::take(&mut environment.calls),
    })
}

fn execute_block(
    statements: &[Statement],
    arguments: &[[u8; 32]],
    parameter_types: &[ValueType],
    locals: &mut Vec<StackValue>,
    meter: &mut GasMeter,
    environment: &mut RuntimeEnvironment<'_>,
) -> Result<StackValue> {
    for statement in statements {
        meter.charge(INSTRUCTION_GAS)?;
        match statement {
            Statement::Let {
                value_type,
                expression,
            }
            | Statement::LetMutable {
                value_type,
                expression,
            } => {
                meter.charge(INSTRUCTION_GAS.saturating_mul(expression.len() as u64))?;
                let value = evaluate_expression(
                    expression,
                    arguments,
                    parameter_types,
                    locals,
                    environment,
                )?;
                if value.value_type != *value_type {
                    bail!("local binding runtime type mismatch");
                }
                locals.push(value);
            }
            Statement::SetLocal { local, expression } => {
                meter.charge(INSTRUCTION_GAS.saturating_mul(expression.len() as u64))?;
                let value = evaluate_expression(
                    expression,
                    arguments,
                    parameter_types,
                    locals,
                    environment,
                )?;
                let binding = locals
                    .get_mut(*local as usize)
                    .ok_or_else(|| anyhow!("runtime local assignment index is out of range"))?;
                if binding.value_type != value.value_type {
                    bail!("local assignment runtime type mismatch");
                }
                *binding = value;
            }
            Statement::Return(expression) => {
                meter.charge(INSTRUCTION_GAS.saturating_mul(expression.len() as u64))?;
                return evaluate_expression(
                    expression,
                    arguments,
                    parameter_types,
                    locals,
                    environment,
                );
            }
            Statement::Store { field, expression } => {
                meter.charge(INSTRUCTION_GAS.saturating_mul(expression.len() as u64))?;
                let field = environment
                    .storage_fields
                    .get(*field as usize)
                    .ok_or_else(|| anyhow!("runtime store field index is out of range"))?;
                let value = evaluate_expression(
                    expression,
                    arguments,
                    parameter_types,
                    locals,
                    environment,
                )?;
                if value.value_type != field.value_type {
                    bail!("storage write runtime type mismatch");
                }
                validate_word(field.value_type, &value.word)?;
                environment
                    .storage
                    .values
                    .insert(field.name.clone(), value.word);
            }
            Statement::Emit { event, values } => {
                let definition = environment
                    .event_definitions
                    .get(*event as usize)
                    .ok_or_else(|| anyhow!("runtime event index is out of range"))?;
                let mut fields = Vec::with_capacity(values.len());
                for (expression, field) in values.iter().zip(&definition.fields) {
                    meter.charge(INSTRUCTION_GAS.saturating_mul(expression.len() as u64))?;
                    let value = evaluate_expression(
                        expression,
                        arguments,
                        parameter_types,
                        locals,
                        environment,
                    )?;
                    if value.value_type != field.value_type {
                        bail!("event field runtime type mismatch");
                    }
                    fields.push((field.name.clone(), field.value_type, value.word));
                }
                environment.events.push(EventRecord {
                    name: definition.name.clone(),
                    fields,
                });
            }
            Statement::Transfer { recipient, amount } => {
                meter.charge(NATIVE_TRANSFER_GAS)?;
                meter.charge(INSTRUCTION_GAS.saturating_mul(recipient.len() as u64))?;
                let recipient = evaluate_expression(
                    recipient,
                    arguments,
                    parameter_types,
                    locals,
                    environment,
                )?;
                meter.charge(INSTRUCTION_GAS.saturating_mul(amount.len() as u64))?;
                let amount =
                    evaluate_expression(amount, arguments, parameter_types, locals, environment)?;
                if recipient.value_type != ValueType::Address
                    || amount.value_type != ValueType::U256
                {
                    bail!("native transfer runtime type mismatch");
                }
                let _ = environment
                    .context
                    .ok_or_else(|| anyhow!("native transfer requires an execution context"))?;
                environment.remaining_balance =
                    subtract_u256(environment.remaining_balance, amount.word)
                        .ok_or_else(|| anyhow!("native transfer exceeds contract balance"))?;
                environment.transfers.push(NativeTransfer {
                    recipient: recipient.word,
                    amount: amount.word,
                });
            }
            Statement::Call {
                target,
                selector,
                value,
            } => {
                meter.charge(CONTRACT_CALL_GAS)?;
                meter.charge(INSTRUCTION_GAS.saturating_mul(target.len() as u64))?;
                let target =
                    evaluate_expression(target, arguments, parameter_types, locals, environment)?;
                meter.charge(INSTRUCTION_GAS.saturating_mul(selector.len() as u64))?;
                let selector =
                    evaluate_expression(selector, arguments, parameter_types, locals, environment)?;
                meter.charge(INSTRUCTION_GAS.saturating_mul(value.len() as u64))?;
                let value =
                    evaluate_expression(value, arguments, parameter_types, locals, environment)?;
                if target.value_type != ValueType::Address
                    || selector.value_type != ValueType::Bytes32
                    || value.value_type != ValueType::U256
                {
                    bail!("contract call runtime type mismatch");
                }
                let context = environment
                    .context
                    .ok_or_else(|| anyhow!("contract call requires an execution context"))?;
                if context.call_depth >= MAX_CALL_DEPTH {
                    bail!("contract call depth limit reached");
                }
                environment.remaining_balance =
                    subtract_u256(environment.remaining_balance, value.word)
                        .ok_or_else(|| anyhow!("contract call value exceeds contract balance"))?;
                environment.calls.push(ContractCall {
                    target: target.word,
                    selector: selector.word,
                    value: value.word,
                    depth: context.call_depth + 1,
                });
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
            } => {
                meter.charge(INSTRUCTION_GAS.saturating_mul(condition.len() as u64))?;
                let condition = evaluate_expression(
                    condition,
                    arguments,
                    parameter_types,
                    locals,
                    environment,
                )?;
                if condition.value_type != ValueType::Bool {
                    bail!("if condition runtime type is not bool");
                }
                let local_count = locals.len();
                let branch = if condition.word == word_from_bool(true) {
                    then_branch
                } else if condition.word == word_from_bool(false) {
                    else_branch
                } else {
                    bail!("if condition is not a canonical bool");
                };
                let result = execute_block(
                    branch,
                    arguments,
                    parameter_types,
                    locals,
                    meter,
                    environment,
                );
                locals.truncate(local_count);
                return result;
            }
        }
    }
    bail!("statement block completed without returning")
}

fn binary_u64(
    stack: &mut Vec<StackValue>,
    operation: fn(u64, u64) -> Option<u64>,
    failure: &str,
) -> Result<()> {
    let (left, right) = pop_u64_pair(stack)?;
    let value = operation(left, right).ok_or_else(|| anyhow!(failure.to_string()))?;
    stack.push(StackValue {
        value_type: ValueType::U64,
        word: word_from_u64(value),
    });
    Ok(())
}

fn pop_u64_pair(stack: &mut Vec<StackValue>) -> Result<(u64, u64)> {
    let right = pop_u64(stack)?;
    let left = pop_u64(stack)?;
    Ok((left, right))
}

fn pop_u64(stack: &mut Vec<StackValue>) -> Result<u64> {
    let value = stack
        .pop()
        .ok_or_else(|| anyhow!("expression stack underflow"))?;
    if value.value_type != ValueType::U64 || value.word[..24] != [0; 24] {
        bail!("expression operand is not a canonical u64");
    }
    Ok(u64::from_be_bytes(value.word[24..].try_into().unwrap()))
}

fn checked_div(left: u64, right: u64) -> Option<u64> {
    left.checked_div(right)
}

fn word_from_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_from_bool(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = u8::from(value);
    word
}

fn subtract_u256(left: [u8; 32], right: [u8; 32]) -> Option<[u8; 32]> {
    if left < right {
        return None;
    }
    let mut result = [0; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let value = left[index] as i16 - right[index] as i16 - borrow;
        if value < 0 {
            result[index] = (value + 256) as u8;
            borrow = 1;
        } else {
            result[index] = value as u8;
            borrow = 0;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lithovm_bytecode::{Function, Program};

    fn u64_word(value: u64) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&value.to_be_bytes());
        word
    }

    #[test]
    fn u256_balance_subtraction_checks_underflow() {
        assert_eq!(subtract_u256([0xff; 32], [0xff; 32]), Some([0; 32]));
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(subtract_u256([0; 32], one), None);
        let mut high = [0; 32];
        high[0] = 1;
        let mut expected = [0xff; 32];
        expected[0] = 0;
        assert_eq!(subtract_u256(high, one), Some(expected));
    }

    #[test]
    fn executes_constant_and_identity_functions() {
        let bytes = Program {
            storage: vec![],
            events: vec![],
            functions: vec![
                Function {
                    name: "answer".into(),
                    parameters: vec![],
                    return_type: ValueType::U64,
                    return_value: ReturnValue::Constant(u64_word(42)),
                },
                Function {
                    name: "echo".into(),
                    parameters: vec![ValueType::U64],
                    return_type: ValueType::U64,
                    return_value: ReturnValue::Parameter(0),
                },
            ],
        }
        .encode()
        .unwrap();
        let vm = Vm::default();
        assert_eq!(
            vm.execute(&bytes, "answer", &[], BASE_CALL_GAS)
                .unwrap()
                .return_value,
            u64_word(42)
        );
        assert_eq!(
            vm.execute(
                &bytes,
                "echo",
                &[u64_word(9005)],
                BASE_CALL_GAS + PARAMETER_GAS
            )
            .unwrap()
            .return_value,
            u64_word(9005)
        );
    }

    #[test]
    fn rejects_bad_calls_before_execution() {
        let bytes = Program {
            storage: vec![],
            events: vec![],
            functions: vec![Function {
                name: "echo".into(),
                parameters: vec![ValueType::Bool],
                return_type: ValueType::Bool,
                return_value: ReturnValue::Parameter(0),
            }],
        }
        .encode()
        .unwrap();
        let vm = Vm::default();
        assert!(vm.execute(&bytes, "missing", &[], 100).is_err());
        assert!(vm.execute(&bytes, "echo", &[], 100).is_err());
        assert!(vm.execute(&bytes, "echo", &[[2; 32]], 100).is_err());
        assert!(vm.execute(&bytes, "echo", &[[0; 32]], 0).is_err());
    }

    #[test]
    fn executes_checked_typed_expressions() {
        let bytes = Program {
            storage: vec![],
            events: vec![],
            functions: vec![Function {
                name: "increment".into(),
                parameters: vec![ValueType::U64],
                return_type: ValueType::U64,
                return_value: ReturnValue::Expression(vec![
                    Instruction::Parameter(0),
                    Instruction::Constant(ValueType::U64, u64_word(1)),
                    Instruction::AddU64,
                ]),
            }],
        }
        .encode()
        .unwrap();
        let gas = BASE_CALL_GAS + PARAMETER_GAS + 3 * INSTRUCTION_GAS;
        assert_eq!(
            Vm::default()
                .execute(&bytes, "increment", &[u64_word(41)], gas)
                .unwrap()
                .return_value,
            u64_word(42)
        );
        assert!(Vm::default()
            .execute(&bytes, "increment", &[u64_word(u64::MAX)], gas)
            .is_err());
    }
}
