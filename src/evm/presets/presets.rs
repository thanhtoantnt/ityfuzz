use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::types::EVMAddress;
use crate::evm::vm::EVMExecutor;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasCaller;
use libafl::prelude::State;
use std::fmt::Debug;

pub trait Preset<I, S, VS>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        evm_executor: &EVMExecutor<I, S, VS, ConciseEVMInput>,
    ) -> Vec<EVMInput>;
}
