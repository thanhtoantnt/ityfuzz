use crate::{
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::{ConciseSerde, VMInputT},
    oracle::{BugMetadata, Oracle, OracleCtx},
    state::HasExecutionResult,
};
use libafl::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    observers::ObserversTuple,
    prelude::{Feedback, HasMetadata, Named},
    state::{HasClientPerfMonitor, HasCorpus, State},
    Error,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    cell::RefCell,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
};

pub struct OracleFeedback<'a, VS, Addr, Code, By, SlotTy, Out, I, S: 'static, CI>
where
    I: VMInputT<VS, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    oracle: &'a Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, SlotTy, Out, I, S, CI>>>>,
    executor: Rc<RefCell<dyn GenericVM<VS, Code, By, Addr, SlotTy, Out, I, S, CI>>>,
    phantom: PhantomData<Out>,
}

impl<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI> Debug
    for OracleFeedback<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI>
where
    I: VMInputT<VS, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI> Named
    for OracleFeedback<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI>
where
    I: VMInputT<VS, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn name(&self) -> &str {
        "OracleFeedback"
    }
}

impl<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI>
    OracleFeedback<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI>
where
    I: VMInputT<VS, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`OracleFeedback`]
    pub fn new(
        oracle: &'a mut Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, SlotTy, Out, I, S, CI>>>>,
        executor: Rc<RefCell<dyn GenericVM<VS, Code, By, Addr, SlotTy, Out, I, S, CI>>>,
    ) -> Self {
        Self {
            oracle,
            executor,
            phantom: Default::default(),
        }
    }
}

impl<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI> Feedback<I, S>
    for OracleFeedback<'a, VS, Addr, Code, By, SlotTy, Out, I, S, CI>
where
    S: State
        + HasClientPerfMonitor
        + HasExecutionResult<Addr, VS, Out, CI>
        + HasCorpus<I>
        + HasMetadata
        + 'static,
    I: VMInputT<VS, Addr, CI> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// since OracleFeedback is just a wrapper around one stateless oracle
    /// we don't need to do initialization
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    /// Called after every execution.
    /// It executes the producers and then oracles after each successful execution.
    /// Returns true if any of the oracle returns true.
    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EMI,
        input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        if state.get_execution_result().reverted {
            return Ok(false);
        }
        {
            if !state.has_metadata::<BugMetadata>() {
                state.metadata_mut().insert(BugMetadata::default());
            }

            state
                .metadata_mut()
                .get_mut::<BugMetadata>()
                .unwrap()
                .current_bugs
                .clear();
        }

        // set up oracle context
        let mut oracle_ctx: OracleCtx<VS, Addr, Code, By, SlotTy, Out, I, S, CI> =
            OracleCtx::new(state, input.get_state(), &mut self.executor, input);

        let mut is_any_bug_hit = false;
        let has_post_exec = oracle_ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .has_post_execution();

        // execute oracles and update stages if needed
        for idx in 0..self.oracle.len() {
            let original_stage = if idx >= input.get_staged_state().stage.len() {
                0
            } else {
                input.get_staged_state().stage[idx]
            };

            for bug_idx in self.oracle[idx]
                .deref()
                .borrow()
                .oracle(&mut oracle_ctx, original_stage)
            {
                let metadata = oracle_ctx
                    .fuzz_state
                    .metadata_mut()
                    .get_mut::<BugMetadata>()
                    .unwrap();
                if metadata.known_bugs.contains(&bug_idx) || has_post_exec {
                    continue;
                }
                metadata.known_bugs.insert(bug_idx);
                metadata.current_bugs.push(bug_idx);
                is_any_bug_hit = true;
            }
        }

        // ensure the execution is finished
        if has_post_exec {
            return Ok(false);
        }

        Ok(is_any_bug_hit)
    }

    // dummy method
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    // dummy method
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}
