use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::EVMBugResult;

use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;
use bytes::Bytes;

use revm_primitives::Bytecode;

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use itertools::Itertools;

pub struct TypedBugOracle {
    address_to_name: HashMap<EVMAddress, String>,
}

impl TypedBugOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
    }
}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for TypedBugOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(
        &self,
        ctx: &mut OracleCtx<
            EVMState,
            EVMAddress,
            Bytecode,
            Bytes,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
            ConciseEVMInput,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        if ctx.post_state.typed_bug.len() > 0 {
            ctx.post_state
                .typed_bug
                .iter()
                .map(|(bug_id, (addr, pc))| {
                    let mut hasher = DefaultHasher::new();
                    bug_id.hash(&mut hasher);
                    pc.hash(&mut hasher);
                    let name = self
                        .address_to_name
                        .get(addr)
                        .unwrap_or(&format!("{:?}", addr))
                        .clone();

                    let real_bug_idx = (hasher.finish() as u64) << 8;
                    EVMBugResult::new(
                        "typed_bug".to_string(),
                        real_bug_idx,
                        format!("{:?} violated", bug_id,),
                        ConciseEVMInput::from_input(
                            ctx.input,
                            ctx.fuzz_state.get_execution_result(),
                        ),
                        None,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    real_bug_idx
                })
                .collect_vec()
        } else {
            vec![]
        }
    }
}
