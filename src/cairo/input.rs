use super::{types::CairoAddress, vm::CairoState};
use crate::input::VMInputT;
use felt::Felt252;
use libafl::prelude::Input;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct CairoInput {
    pub repeat: usize,

    pub felts: Vec<Felt252>,
}

impl VMInputT<CairoState, CairoAddress> for CairoInput {
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
}

impl Input for CairoInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }
    fn wrapped_as_testcase(&mut self) {}
}

impl std::fmt::Debug for CairoInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CairoInput").finish()
    }
}
