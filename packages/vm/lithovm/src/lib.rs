use anyhow::{anyhow, bail, Result};
use lithovm_bytecode::{parse, validate_word, Program, ReturnValue, ValueType};
use lithovm_receipts::ReceiptV1;
use lithovm_zk_verifier::{StubVerifier, ZkVerifier};

/// Minimal LithoVM execution context (scaffold).
pub struct Vm {
    verifier: Box<dyn ZkVerifier + Send + Sync>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub return_type: ValueType,
    pub return_value: [u8; 32],
    pub gas_used: u64,
}

pub const BASE_CALL_GAS: u64 = 10;
pub const PARAMETER_GAS: u64 = 2;

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
        execute_program(&program, function_name, arguments, gas_limit)
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
    let gas_used = BASE_CALL_GAS
        .checked_add(PARAMETER_GAS.saturating_mul(arguments.len() as u64))
        .ok_or_else(|| anyhow!("gas calculation overflow"))?;
    if gas_limit < gas_used {
        bail!("out of gas: requires {gas_used}, limit is {gas_limit}");
    }
    let return_value = match function.return_value {
        ReturnValue::Constant(word) => word,
        ReturnValue::Parameter(index) => arguments[index as usize],
    };
    Ok(ExecutionResult {
        return_type: function.return_type,
        return_value,
        gas_used,
    })
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
    fn executes_constant_and_identity_functions() {
        let bytes = Program {
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
}
