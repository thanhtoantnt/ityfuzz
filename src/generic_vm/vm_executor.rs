use crate::generic_vm::vm_state::VMStateT;

use crate::state_input::StagedVMState;

use crate::input::ConciseSerde;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub const MAP_SIZE: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult<Addr, VS, Out, CI>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    pub output: Out,
    pub reverted: bool,
    #[serde(deserialize_with = "StagedVMState::deserialize")]
    pub new_state: StagedVMState<Addr, VS, CI>,
    pub additional_info: Option<Vec<u8>>,
}

impl<Addr, VS, Out, CI> ExecutionResult<Addr, VS, Out, CI>
where
    VS: Default + VMStateT + 'static,
    Addr: Serialize + DeserializeOwned + Debug,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    pub fn empty_result() -> Self {
        Self {
            output: Out::default(),
            reverted: false,
            new_state: StagedVMState::new_uninitialized(),
            additional_info: None,
        }
    }
}

pub trait GenericVM<VS, Code, By, Addr, Out, I, S, CI> {
    fn deploy(
        &mut self,
        code: Code,
        constructor_args: Option<By>,
        deployed_address: Addr,
        state: &mut S,
    ) -> Option<Addr>;
    fn execute(&mut self, input: &I, state: &mut S) -> ExecutionResult<Addr, VS, Out, CI>
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Out: Default,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static;

    fn state_changed(&self) -> bool;
    fn as_any(&mut self) -> &mut dyn std::any::Any;
}
