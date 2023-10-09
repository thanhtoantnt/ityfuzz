use crate::state::FuzzState;

use super::{
    input::{CairoInput, ConciseCairoInput},
    vm::CairoState,
};

pub type CairoAddress = usize;
pub type CairoFuzzState =
    FuzzState<CairoInput, CairoState, CairoAddress, Vec<u8>, ConciseCairoInput>;
// pub type CairoOracleCtx<'a> = OracleCtx<'a, CairoState, CairoAddress, CairoInput, CairoFuzzState>;

// pub type CairoFuzzMutator<'a> = FuzzMutator<
//     'a,
//     CairoState,
//     CairoAddress,
//     SortedDroppingScheduler<StagedVMState<CairoState>, InfantState<CairoState>>,
// >;

// pub type CairoStagedVMState = StagedVMState<CairoState>;

// pub type CairoInfantState = InfantState<CairoState>;