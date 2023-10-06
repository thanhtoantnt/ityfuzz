/// Implements wrappers around VMState that can be stored in a corpus.
use libafl::inputs::Input;

use std::fmt::Debug;

use crate::generic_vm::vm_state::VMStateT;

use crate::input::ConciseSerde;
use crate::tracer::TxnTrace;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// StagedVMState is a wrapper around a VMState that can be stored in a corpus.
/// It also has stage field that is used to store the stage of the oracle execution on such a VMState.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StagedVMState<Addr, VS, CI>
where
    VS: Default + VMStateT,
    Addr: Debug,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    #[serde(deserialize_with = "VS::deserialize")]
    pub state: VS, // VM state
    pub stage: Vec<u64>,
    pub initialized: bool,
    #[serde(deserialize_with = "TxnTrace::deserialize")]
    pub trace: TxnTrace<Addr, CI>, // Trace building up such a VMState
}

impl<Addr, VS, CI> StagedVMState<Addr, VS, CI>
where
    VS: Default + VMStateT,
    Addr: Debug,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new StagedVMState with a given VMState
    pub fn new_with_state(state: VS) -> Self {
        Self {
            state,
            stage: vec![],
            initialized: true,
            trace: TxnTrace::new(),
        }
    }

    /// Create a new uninitialized StagedVMState
    pub fn new_uninitialized() -> Self {
        Self {
            state: Default::default(),
            stage: vec![],
            initialized: false,
            trace: TxnTrace::new(),
        }
    }
}

impl<Addr, VS, CI> Input for StagedVMState<Addr, VS, CI>
where
    VS: Default + VMStateT,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{}.state", idx)
    }
}
