use crate::generic_vm::vm_state::VMStateT;
use crate::input::ConciseSerde;
use crate::state::HasInfantStateState;
use libafl::corpus::Corpus;
use libafl::prelude::HasCorpus;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Represent a trace of transactions with starting VMState ID (from_idx).
/// If VMState ID is None, it means that the trace is from the initial state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnTrace<Addr, CI> {
    pub transactions: Vec<CI>,
    pub from_idx: Option<usize>,
    pub phantom: std::marker::PhantomData<Addr>,
}

impl<Addr, CI> TxnTrace<Addr, CI>
where
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new TxnTrace
    pub(crate) fn new() -> Self {
        Self {
            transactions: Vec::new(),
            from_idx: None,
            phantom: Default::default(),
        }
    }

    /// Add a transaction to the trace
    pub fn add_input(&mut self, input: CI) {
        self.transactions.push(input);
    }

    /// Convert the trace to a human-readable string
    pub fn to_string<VS, S>(&self, state: &mut S) -> String
    where
        S: HasInfantStateState<Addr, VS, CI>,
        VS: VMStateT,
        Addr: Debug + Serialize + DeserializeOwned + Clone,
    {
        // If from_idx is None, it means that the trace is from the initial state
        if self.from_idx.is_none() {
            return String::from("Begin\n");
        }
        let current_idx = self.from_idx.unwrap();
        let corpus_item = state.get_infant_state_state().corpus().get(current_idx);
        // This happens when full_trace feature is not enabled, the corpus item may be discarded
        if corpus_item.is_err() {
            return String::from("Corpus returning error\n");
        }
        let testcase = corpus_item.unwrap().clone().into_inner();
        let testcase_input = testcase.input();
        if testcase_input.is_none() {
            return String::from("[REDACTED]\n");
        }

        // Try to reconstruct transactions leading to the current VMState recursively
        let mut s = Self::to_string(&testcase_input.as_ref().unwrap().trace.clone(), state);

        // Dump the current transaction
        for concise_input in &self.transactions {
            s.push_str(format!("{}\n", concise_input.serialize_string()).as_str());
        }
        s
    }
}

impl<Addr, CI> Default for TxnTrace<Addr, CI>
where
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn default() -> Self {
        Self::new()
    }
}
