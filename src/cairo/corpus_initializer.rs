use libafl::prelude::Corpus;
use libafl::schedulers::Scheduler;
use libafl::{corpus::Testcase, state::HasCorpus};

use std::time::Duration;

use crate::state_input::StagedVMState;

use super::{
    input::{CairoInput, ConciseCairoInput},
    types::{CairoFuzzState, CairoInfantStateState, CairoStagedVMState},
    vm::{CairoExecutor, CairoState},
};

pub struct CairoCorpusInitializer<'a> {
    pub executor: &'a mut CairoExecutor<CairoInput, CairoFuzzState, CairoState, ConciseCairoInput>,
    pub scheduler: &'a dyn Scheduler<CairoInput, CairoFuzzState>,
    pub infant_scheduler: &'a dyn Scheduler<CairoStagedVMState, CairoInfantStateState>,
    pub state: &'a mut CairoFuzzState,
    pub work_dir: String,
}

macro_rules! wrap_input {
    ($input: expr) => {{
        let mut tc = Testcase::new($input);
        tc.set_exec_time(Duration::from_secs(0));
        tc
    }};
}

macro_rules! add_input_to_corpus {
    ($state: expr, $scheduler: expr, $input: expr) => {
        let idx = $state
            .add_tx_to_corpus(wrap_input!($input))
            .expect("failed to add");
        $scheduler
            .on_add($state, idx)
            .expect("failed to call scheduler on_add");
    };
}

impl<'a> CairoCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut CairoExecutor<CairoInput, CairoFuzzState, CairoState, ConciseCairoInput>,
        scheduler: &'a dyn Scheduler<CairoInput, CairoFuzzState>,
        infant_scheduler: &'a dyn Scheduler<CairoStagedVMState, CairoInfantStateState>,
        state: &'a mut CairoFuzzState,
        work_dir: String,
    ) -> Self {
        Self {
            executor,
            scheduler,
            infant_scheduler,
            state,
            work_dir,
        }
    }

    pub fn initialize(&mut self) {
        let input = CairoInput {
            repeat: 1,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            felts: vec![],
            max_input_size: 1024,
        };

        add_input_to_corpus!(self.state, self.scheduler, input);

        let mut tc = Testcase::new(StagedVMState::new_with_state(CairoState::default()));
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .state
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        self.infant_scheduler
            .on_add(&mut self.state.infant_states_state, idx)
            .expect("failed to call infant scheduler on_add");
    }
}
