use crate::generic_vm::vm_executor::GenericVM;
use libafl::state::{HasCorpus, HasMetadata, HasRand, State};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, marker::PhantomData};

use crate::{
    input::VMInputT,
    state::{HasCaller, HasCurrentInputIdx},
    state_input::StagedVMState,
};

use super::types::CairoAddress;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CairoState {
    pub bug_hit: bool,
}

impl CairoState {
    pub(crate) fn new() -> Self {
        Self { bug_hit: false }
    }
}
impl Default for CairoState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CairoExecutor<I, S, VS, CI>
where
    S: State + HasCaller<CairoAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, CairoAddress, ConciseCairoInput>,
    VS: Clone + Debug + Default + Serialize + DeserializeOwned,
{
    phantom: PhantomData<(VS, I, S, CI)>,
}

impl<I, S, VS> CairoExecutor<I, S, VS>
where
    S: State + HasCaller<CairoAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, CairoAddress>,
    VS: Clone + Debug + Default + Serialize + DeserializeOwned,
{
    pub fn new() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<VS, I, S> GenericVM<VS, CairoAddress, I, S> for CairoExecutor<I, S, VS>
where
    I: VMInputT<VS, CairoAddress> + 'static,
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
    VS: Clone + Debug + Default + Serialize + DeserializeOwned + Default + 'static,
{
    fn execute(&mut self, _input: &I, _state: &mut S) -> StagedVMState<VS> {
        todo!()
    }
}
