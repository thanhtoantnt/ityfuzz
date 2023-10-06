/// Analysis passes for EVM bytecode
use crate::mutation_utils::ConstantPoolMetadata;
use libafl::state::{HasMetadata, State};

use crate::evm::bytecode_iterator::all_bytecode;
use revm_interpreter::opcode::JUMPI;
use revm_primitives::Bytecode;
use std::collections::HashSet;

/// Find all constants in the bytecode by observing PUSH instructions.
///
/// Check tests below for usage.
pub fn find_constants(bytecode: &Bytecode) -> HashSet<Vec<u8>> {
    let bytecode_len = bytecode.len();
    let mut constants = HashSet::new();
    let bytes = bytecode.bytes();

    let avail_bytecode = all_bytecode(&bytes.to_vec());
    for (pc, op) in avail_bytecode {
        if op >= 0x60 && op <= 0x7f {
            let next_op = if pc + op as usize - 0x5e < bytecode_len {
                bytes[pc + op as usize - 0x5e]
            } else {
                break;
            };
            if next_op == JUMPI {
                continue;
            }
            if op as usize - 0x60 + 1 >= 5 {
                let mut data = vec![0u8; op as usize - 0x60 + 1];
                let mut i = 0;
                while i < op - 0x60 + 1 {
                    let offset = i as usize;
                    data[offset] = bytes[pc + offset + 1];
                    i += 1;
                }
                constants.insert(data);
            }
        }
    }
    constants
}

/// Add constants in smart contract to the global state's [`ConstantPoolMetadata`]
/// this can be costly, ensure sampling to be cheap
pub fn add_analysis_result_to_state<S>(bytecode: &Bytecode, state: &mut S)
where
    S: HasMetadata + State,
{
    let constants = find_constants(bytecode);
    match state.metadata_mut().get_mut::<ConstantPoolMetadata>() {
        Some(meta) => {
            for constant in constants {
                if !meta.constants.contains(&constant) {
                    meta.constants.push(constant);
                }
            }
        }
        None => {
            state.metadata_mut().insert(ConstantPoolMetadata {
                constants: constants.into_iter().collect(),
            });
        }
    }
}
