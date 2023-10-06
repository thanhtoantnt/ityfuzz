use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::EVMBugResult;

use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, ProjectSourceMapTy, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;
use bytes::Bytes;

use revm_primitives::Bytecode;

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::evm::blaz::builder::{ArtifactInfoMetadata, BuildJobResult};
use crate::evm::oracles::TYPED_BUG_BUG_IDX;
use itertools::Itertools;
use libafl::state::HasMetadata;

pub struct TypedBugOracle {
    sourcemap: ProjectSourceMapTy,
    address_to_name: HashMap<EVMAddress, String>,
}

impl TypedBugOracle {
    pub fn new(
        sourcemap: ProjectSourceMapTy,
        address_to_name: HashMap<EVMAddress, String>,
    ) -> Self {
        Self {
            sourcemap,
            address_to_name,
        }
    }
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
    > for TypedBugOracle
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
            EVMU256,
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

                    let real_bug_idx = (hasher.finish() as u64) << 8 + TYPED_BUG_BUG_IDX;
                    let srcmap = BuildJobResult::get_sourcemap_executor(
                        ctx.fuzz_state
                            .metadata_mut()
                            .get_mut::<ArtifactInfoMetadata>()
                            .expect("get metadata failed")
                            .get_mut(addr),
                        ctx.executor,
                        addr,
                        &self.sourcemap,
                        *pc,
                    );
                    EVMBugResult::new(
                        "typed_bug".to_string(),
                        real_bug_idx,
                        format!("{:?} violated", bug_id,),
                        ConciseEVMInput::from_input(
                            ctx.input,
                            ctx.fuzz_state.get_execution_result(),
                        ),
                        srcmap,
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
