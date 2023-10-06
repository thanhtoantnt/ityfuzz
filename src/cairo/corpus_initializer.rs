use libafl::corpus::Testcase;
use libafl::schedulers::Scheduler;

use std::time::Duration;

use crate::{add_input_to_corpus, wrap_input};

use super::{
    input::CairoInput,
    types::{CairoFuzzState, CairoInfantState, CairoStagedVMState},
    vm::{CairoExecutor, CairoState},
};

pub struct CairoCorpusInitializer<'a> {
    pub executor: &'a mut CairoExecutor<CairoInput, CairoFuzzState, CairoState>,
    pub infant_scheduler: &'a dyn Scheduler<CairoStagedVMState, CairoInfantState>,
    pub state: &'a mut CairoFuzzState,
}

impl<'a> CairoCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut CairoExecutor<CairoInput, CairoFuzzState, CairoState>,
        infant_scheduler: &'a dyn Scheduler<CairoStagedVMState, CairoInfantState>,
        state: &'a mut CairoFuzzState,
    ) -> Self {
        Self {
            executor,
            infant_scheduler,
            state,
        }
    }

    pub fn initialize(&mut self, _input_file: String) {
        // Initialization
        self.initialize_corpus();
    }

    fn initialize_corpus(&mut self) {
        let input = CairoInput {
            repeat: 1,
            felts: vec![],
        };
        add_input_to_corpus!(self.state, input);
    }
}
