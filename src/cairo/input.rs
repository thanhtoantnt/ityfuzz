use super::{types::CairoAddress, vm::CairoState};
use crate::{
    input::{ConciseSerde, VMInputT},
    state_input::StagedVMState,
};
use felt::Felt252;
use libafl::prelude::Input;
use serde::{Deserialize, Serialize};

use std::fmt::Debug;

#[derive(Serialize, Deserialize, Clone)]
pub struct CairoInput {
    pub repeat: usize,

    pub felts: Vec<Felt252>,

    /// Staged VM state
    #[serde(skip_deserializing)]
    pub sstate: StagedVMState<CairoAddress, CairoState, ConciseCairoInput>,

    /// Staged VM state index in the corpus
    #[serde(skip_deserializing)]
    pub sstate_idx: usize,

    /// Maximum size to allow inputs to expand to
    pub max_input_size: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConciseCairoInput {
    pub repeat: usize,

    pub felts: Vec<Felt252>,
}

impl ConciseSerde for ConciseCairoInput {
    fn serialize_concise(&self) -> Vec<u8> {
        todo!()
    }

    fn deserialize_concise(_data: &[u8]) -> Self {
        todo!()
    }

    fn serialize_string(&self) -> String {
        todo!()
    }
}
impl VMInputT<CairoState, CairoAddress, ConciseCairoInput> for CairoInput {
    fn mutate<S>(&mut self, _state: &mut S) -> libafl::prelude::MutationResult
    where
        S: libafl::state::State
            + libafl::state::HasRand
            + libafl::state::HasMaxSize
            + crate::state::HasCaller<CairoAddress>
            + libafl::state::HasMetadata,
    {
        todo!()
    }

    fn get_caller(&self) -> CairoAddress {
        todo!()
    }

    fn set_caller(&mut self, _caller: CairoAddress) {
        todo!()
    }

    fn get_contract(&self) -> CairoAddress {
        todo!()
    }

    fn get_state(&self) -> &CairoState {
        todo!()
    }

    fn get_caller_mut(&mut self) -> &mut CairoAddress {
        todo!()
    }

    fn get_state_mut(&mut self) -> &mut CairoState {
        todo!()
    }

    fn set_staged_state(
        &mut self,
        state: crate::state_input::StagedVMState<CairoAddress, CairoState, ConciseCairoInput>,
        idx: usize,
    ) {
        self.sstate = state;
        self.sstate_idx = idx;
    }

    fn get_state_idx(&self) -> usize {
        todo!()
    }

    fn get_staged_state(
        &self,
    ) -> &crate::state_input::StagedVMState<CairoAddress, CairoState, ConciseCairoInput> {
        &self.sstate
    }

    fn set_as_post_exec(&mut self, _out_size: usize) {
        todo!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn fav_factor(&self) -> f64 {
        todo!()
    }

    fn get_data_abi(&self) -> Option<crate::evm::abi::BoxedABI> {
        todo!()
    }

    fn get_data_abi_mut(&mut self) -> &mut Option<crate::evm::abi::BoxedABI> {
        todo!()
    }

    fn get_txn_value_temp(&self) -> Option<crate::evm::types::EVMU256> {
        todo!()
    }

    fn get_direct_data(&self) -> Vec<u8> {
        todo!()
    }

    fn get_concise<Out: Default>(
        &self,
        _exec_res: &crate::generic_vm::vm_executor::ExecutionResult<
            CairoAddress,
            CairoState,
            Out,
            ConciseCairoInput,
        >,
    ) -> ConciseCairoInput {
        todo!()
    }
}

impl Input for CairoInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }
    fn wrapped_as_testcase(&mut self) {}
}

impl Debug for CairoInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CairoInput").finish()
    }
}
