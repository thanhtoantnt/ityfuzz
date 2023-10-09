use libafl::state::{HasCorpus, HasMetadata, HasRand, State};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::{ConciseSerde, VMInputT},
    state::{HasCaller, HasCurrentInputIdx},
};

use super::{input::ConciseCairoInput, types::CairoAddress};

use std::{fmt::Debug, marker::PhantomData};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CairoState {
    // State of the Cairo Program
    pub state: Vec<(u32, u32)>,

    pub bug_hit: bool,
}

impl CairoState {
    pub(crate) fn new() -> Self {
        Self {
            state: vec![],
            bug_hit: false,
        }
    }
}
impl Default for CairoState {
    fn default() -> Self {
        Self::new()
    }
}

impl VMStateT for CairoState {
    fn get_hash(&self) -> u64 {
        todo!()
    }

    fn has_post_execution(&self) -> bool {
        todo!()
    }

    fn get_post_execution_needed_len(&self) -> usize {
        todo!()
    }

    fn get_post_execution_pc(&self) -> usize {
        todo!()
    }

    fn get_post_execution_len(&self) -> usize {
        todo!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }

    fn is_subset_of(&self, _other: &Self) -> bool {
        todo!()
    }
}

// Executor, similar to a runner
#[derive(Debug, Clone)]
pub struct CairoExecutor<I, S, VS, CI>
where
    S: State + HasCaller<CairoAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, CairoAddress, ConciseCairoInput>,
    VS: VMStateT,
{
    phantom: PhantomData<(VS, I, S, CI)>,
}

impl<I, S, VS, CI> CairoExecutor<I, S, VS, CI>
where
    S: State + HasCaller<CairoAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, CairoAddress, ConciseCairoInput>,
    VS: VMStateT,
{
    pub fn new() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<VS, I, S, CI> GenericVM<VS, usize, usize, CairoAddress, Vec<u8>, I, S, CI>
    for CairoExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, CairoAddress, ConciseCairoInput> + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasMetadata
        + HasCaller<CairoAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
{
    fn deploy(
        &mut self,
        _code: usize,
        _constructor_args: Option<usize>,
        _deployed_address: CairoAddress,
        _state: &mut S,
    ) -> Option<CairoAddress> {
        todo!()
    }

    fn execute(
        &mut self,
        _input: &I,
        _state: &mut S,
    ) -> crate::generic_vm::vm_executor::ExecutionResult<CairoAddress, VS, Vec<u8>, CI>
    where
        VS: VMStateT,
        CairoAddress: Serialize + DeserializeOwned + Debug,
        Vec<u8>: Default,
        CI: Serialize + DeserializeOwned + Debug + Clone + crate::input::ConciseSerde + 'static,
    {
        todo!()
    }

    fn state_changed(&self) -> bool {
        todo!()
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        todo!()
    }
}
