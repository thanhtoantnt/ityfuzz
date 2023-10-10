use crate::{
    mutator::FuzzMutator,
    scheduler::SortedDroppingScheduler,
    state::{FuzzState, InfantStateState},
    state_input::StagedVMState,
};

use super::{
    input::{CairoInput, ConciseCairoInput},
    vm::CairoState,
};

pub type CairoAddress = usize;
pub type CairoFuzzState =
    FuzzState<CairoInput, CairoState, CairoAddress, Vec<(u32, u32)>, ConciseCairoInput>;

pub type CairoFuzzMutator<'a> = FuzzMutator<
    'a,
    CairoState,
    CairoAddress,
    CairoAddress,
    SortedDroppingScheduler<
        StagedVMState<CairoAddress, CairoState, ConciseCairoInput>,
        InfantStateState<CairoAddress, CairoState, ConciseCairoInput>,
    >,
    ConciseCairoInput,
>;

pub type CairoStagedVMState = StagedVMState<CairoAddress, CairoState, ConciseCairoInput>;

pub type CairoInfantStateState = InfantStateState<CairoAddress, CairoState, ConciseCairoInput>;

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub entrypoint: String,
    pub num_args: u64,
    pub type_args: Vec<String>,
    pub hints: bool,
    pub decorators: Vec<String>,
}
