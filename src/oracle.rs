/// Implementation of the oracle (i.e., invariant checker)
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::{ConciseSerde, VMInputT};
use crate::state::HasExecutionResult;

use libafl::impl_serdeany;
use libafl::prelude::{HasCorpus, HasMetadata, SerdeAnyMap};
use libafl::state::State;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;

/// The context passed to the oracle
pub struct OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// The state of the fuzzer
    pub fuzz_state: &'a mut S,
    /// The VMState before the execution
    pub pre_state: &'a VS,
    /// The VMState after the execution
    pub post_state: VS,
    /// The metadata of the oracle
    pub metadata: SerdeAnyMap,
    /// The executor
    pub executor:
        &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
    /// The input executed by the VM
    pub input: &'a I,
    pub phantom: PhantomData<Addr>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>
    OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + 'static,
    S: State + HasCorpus<I> + HasMetadata + HasExecutionResult<Loc, Addr, VS, Out, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new oracle context
    pub fn new(
        fuzz_state: &'a mut S,
        pre_state: &'a VS,
        executor: &'a mut Rc<
            RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>,
        >,
        input: &'a I,
    ) -> Self {
        Self {
            post_state: fuzz_state.get_execution_result().new_state.state.clone(),
            fuzz_state,
            pre_state,
            metadata: SerdeAnyMap::new(),
            executor,
            input,
            phantom: Default::default(),
        }
    }

}

/// Producer trait provides functions needed to produce data for the oracle
pub trait Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Produce data for the oracle, called everytime before any oracle is called
    fn produce(&mut self, ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>);
    /// Cleanup. Called everytime after the oracle is called
    fn notify_end(&mut self, ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>);
}

/// Oracle trait provides functions needed to implement an oracle
pub trait Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Transition function, called everytime after non-reverted execution
    fn transition(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>,
        stage: u64,
    ) -> u64;

    /// Oracle function, called everytime after non-reverted execution
    /// Returns Some(bug_idx) if the oracle is violated
    fn oracle(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>,
        stage: u64,
    ) -> Vec<u64>;
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BugMetadata {
    pub known_bugs: HashSet<u64>,
    pub current_bugs: Vec<u64>,
    pub corpus_idx_to_bug: HashMap<usize, Vec<u64>>,
}

impl BugMetadata {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register_corpus_idx(&mut self, corpus_idx: usize) {
        self.corpus_idx_to_bug
            .insert(corpus_idx, self.current_bugs.clone());
    }
}

impl_serdeany!(BugMetadata);
