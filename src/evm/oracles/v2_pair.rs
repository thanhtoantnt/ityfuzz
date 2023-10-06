use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::{dummy_precondition, EVMBugResult};
use crate::evm::oracles::V2_PAIR_BUG_IDX;
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{bytes_to_u64, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::fuzzer::ORACLE_OUTPUT;
use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;

pub struct PairBalanceOracle {
    pub pair_producer: Rc<RefCell<PairProducer>>,
}

impl PairBalanceOracle {
    pub fn new(pair_producer: Rc<RefCell<PairProducer>>) -> Self {
        Self { pair_producer }
    }
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
    > for PairBalanceOracle
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
            EVMAddress,
            EVMU256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
            ConciseEVMInput,
        >,
        stage: u64,
    ) -> Vec<u64> {
        panic!("Flashloan v2 required to use pair (-p).")
    }
}
