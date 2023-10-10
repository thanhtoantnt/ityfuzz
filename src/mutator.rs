use crate::{
    generic_vm::vm_state::VMStateT,
    input::{ConciseSerde, VMInputT},
    state::{HasCaller, HasItyState, InfantStateState},
    state_input::StagedVMState,
};
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, Mutator, Rand, State};
use libafl::schedulers::Scheduler;
use libafl::state::HasMetadata;
use libafl::Error;
use revm_interpreter::Interpreter;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// [`AccessPattern`] records the access pattern of the input during execution. This helps
/// to determine what is needed to be fuzzed. For instance, we don't need to mutate caller
/// if the execution never uses it.
///
/// Each mutant should report to its parent's access pattern
/// if a new corpus item is added, it should inherit the access pattern of its source
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AccessPattern {
    pub caller: bool, // or origin
    pub call_value: bool,
    pub gas_price: bool,
    pub number: bool,
    pub coinbase: bool,
    pub timestamp: bool,
    pub prevrandao: bool,
    pub gas_limit: bool,
    pub chain_id: bool,
    pub basefee: bool,
}

impl AccessPattern {
    /// Create a new access pattern with all fields set to false
    pub fn new() -> Self {
        Self {
            caller: false,
            call_value: false,
            gas_price: false,
            number: false,
            coinbase: false,
            timestamp: false,
            prevrandao: false,
            gas_limit: false,
            chain_id: false,
            basefee: false,
        }
    }

    /// Record access pattern of current opcode executed by the interpreter
    pub fn decode_instruction(&mut self, interp: &Interpreter) {
        match unsafe { *interp.instruction_pointer } {
            0x33 => self.caller = true,
            0x34 => {
                // prevent initial check of dispatch to fallback
                if interp.program_counter() > 0xb {
                    self.call_value = true;
                }
            }
            0x3a => self.gas_price = true,
            0x43 => self.number = true,
            0x41 => self.coinbase = true,
            0x42 => self.timestamp = true,
            0x44 => self.prevrandao = true,
            0x45 => self.gas_limit = true,
            0x46 => self.chain_id = true,
            0x48 => self.basefee = true,
            _ => {}
        }
    }
}

/// [`FuzzMutator`] is a mutator that mutates the input based on the ABI and access pattern
pub struct FuzzMutator<'a, VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<StagedVMState<Addr, VS, CI>, InfantStateState<Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Scheduler for selecting the next VM state to use if we decide to mutate the VM state of
    /// the input
    pub infant_scheduler: &'a SC,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr, CI)>,
}

impl<'a, VS, Loc, Addr, SC, CI> FuzzMutator<'a, VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<StagedVMState<Addr, VS, CI>, InfantStateState<Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`FuzzMutator`] with the given scheduler
    pub fn new(infant_scheduler: &'a SC) -> Self {
        Self {
            infant_scheduler,
            phantom: Default::default(),
        }
    }
}

impl<'a, VS, Loc, Addr, I, S, SC, CI> Mutator<I, S> for FuzzMutator<'a, VS, Loc, Addr, SC, CI>
where
    I: VMInputT<VS, Addr, CI> + Input,
    S: State + HasRand + HasMaxSize + HasItyState<Addr, VS, CI> + HasCaller<Addr> + HasMetadata,
    SC: Scheduler<StagedVMState<Addr, VS, CI>, InfantStateState<Addr, VS, CI>>,
    VS: Default + VMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Mutate the input
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // if the VM state of the input is not initialized, swap it with a state initialized
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }

        // determine whether we should conduct havoc
        // (a sequence of mutations in batch vs single mutation)
        let should_havoc = state.rand_mut().below(100) < 60;

        // determine how many times we should mutate the input
        let havoc_times = if should_havoc {
            state.rand_mut().below(10) + 1
        } else {
            1
        };

        let mut already_crossed = false;

        // mutate the input once
        let mut mutator = || -> MutationResult {
            match state.rand_mut().below(100) {
                0..=5 => {
                    if already_crossed {
                        return MutationResult::Skipped;
                    }
                    already_crossed = true;
                    // cross over infant state
                    let old_idx = input.get_state_idx();
                    let (idx, new_state) = state.get_infant_state(self.infant_scheduler).unwrap();
                    if idx == old_idx {
                        return MutationResult::Skipped;
                    }
                    if !state.has_caller(&input.get_caller()) {
                        input.set_caller(state.get_rand_caller());
                    }

                    input.set_staged_state(new_state, idx);
                    MutationResult::Mutated
                }
                11 => MutationResult::Mutated,
                _ => input.mutate(state),
            }
        };

        let mut res = MutationResult::Skipped;
        let mut tries = 0;

        while res != MutationResult::Mutated && tries < 20 {
            for _ in 0..havoc_times {
                if mutator() == MutationResult::Mutated {
                    res = MutationResult::Mutated;
                }
            }
            tries += 1;
        }
        Ok(res)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        // todo!()
        Ok(())
    }
}
