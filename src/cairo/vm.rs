use felt::Felt252;
use libafl::state::{HasCorpus, HasMetadata, HasRand, State};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    generic_vm::{
        vm_executor::{ExecutionResult, GenericVM},
        vm_state::VMStateT,
    },
    input::{ConciseSerde, VMInputT},
    state::{HasCaller, HasCurrentInputIdx},
    state_input::StagedVMState,
};

use cairo_rs::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
};

use super::{
    input::{CairoInput, ConciseCairoInput},
    types::{CairoAddress, Function},
};

use std::{fmt::Debug, marker::PhantomData};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CairoState {
    // State of the Cairo Program
    pub state: Vec<(u32, u32)>,

    pub bug_hit: bool,

    // pub func_name: Option<String>,
    pub typed_bug: Vec<String>,
}

impl CairoState {
    pub(crate) fn new() -> Self {
        Self {
            state: vec![],
            typed_bug: vec![],
            // func_name,
            bug_hit: false,
        }
    }
}

impl Default for CairoState {
    fn default() -> Self {
        Self::new()
    }
}

impl VMStateT for CairoState {
    fn get_hash(&self) -> u64 {
        todo!()
    }

    // fn has_post_execution(&self) -> bool {
    //     self.post_execution.len() > 0
    // }

    fn get_post_execution_needed_len(&self) -> usize {
        todo!()
    }

    fn get_post_execution_pc(&self) -> usize {
        todo!()
    }

    fn get_post_execution_len(&self) -> usize {
        todo!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }

    fn is_subset_of(&self, _other: &Self) -> bool {
        todo!()
    }
}

// Executor, similar to a runner
#[derive(Debug, Clone)]
pub struct CairoExecutor<I, S, VS, CI>
where
    S: State + HasCaller<CairoAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, CairoAddress, ConciseCairoInput>,
    VS: VMStateT,
{
    program: Program,
    function: Function,
    phantom: PhantomData<(VS, I, S, CI)>,
}

impl<I, S, VS, CI> CairoExecutor<I, S, VS, CI>
where
    S: State + HasCaller<CairoAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, CairoAddress, ConciseCairoInput>,
    VS: VMStateT,
{
    pub fn new(program: Program, function: Function) -> Self {
        Self {
            program,
            function,
            phantom: Default::default(),
        }
    }
}

pub trait HasCairoInput {
    fn get_felts(&self) -> Vec<Felt252>;
}

impl HasCairoInput for CairoInput {
    fn get_felts(&self) -> Vec<Felt252> {
        self.felts.clone()
    }
}

impl HasFunctionName for CairoInput {
    fn get_function(&self) -> String {
        self.func_name.clone()
    }
}

trait HasFunctionName {
    fn get_function(&self) -> String;
}

impl<VS, I, S, CI> GenericVM<VS, usize, usize, CairoAddress, Vec<(u32, u32)>, I, S, CI>
    for CairoExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, CairoAddress, ConciseCairoInput> + HasFunctionName + HasCairoInput + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasMetadata
        + HasCaller<CairoAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
{
    fn deploy(
        &mut self,
        _code: usize,
        _constructor_args: Option<usize>,
        _deployed_address: CairoAddress,
        _state: &mut S,
    ) -> Option<CairoAddress> {
        todo!()
    }

    fn execute(
        &mut self,
        _input: &I,
        _state: &mut S,
    ) -> ExecutionResult<CairoAddress, VS, Vec<(u32, u32)>, CI>
    where
        VS: VMStateT,
        CairoAddress: Serialize + DeserializeOwned + Debug,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    {
        println!("input: {:?}", _input);
        let mut cairo_runner = CairoRunner::new(&self.program, "small", false)
            .expect("Failed to init the CairoRunner");

        let mut vm = VirtualMachine::new(true);
        let mut hint_processor = BuiltinHintProcessor::new_empty();

        // Set the entrypoint which is the function the user want to fuzz
        let entrypoint = match self
            .program
            .get_identifier(&format!("__main__.{}", &_input.get_function()))
            .expect("Failed to initialize entrypoint")
            .pc
        {
            Some(value) => value,
            None => todo!("Check the return value"),
        };

        // Init builtins and segments
        cairo_runner
            .initialize_builtins(&mut vm)
            .expect("Failed to initialize builtins");
        cairo_runner.initialize_segments(&mut vm, None);

        // Init the vector of arguments
        let mut args = Vec::<MaybeRelocatable>::new();
        // Set the entrypoint selector
        let entrypoint_selector = MaybeRelocatable::from(Felt252::new(entrypoint));

        let value_one = MaybeRelocatable::from((2, 0));
        args.push(entrypoint_selector);
        args.push(value_one);

        let mut felts = _input.get_felts();
        if felts.is_empty() {
            felts.extend_from_slice(&vec![Felt252::from(b'\0'); self.function.num_args as usize]);
        }
        let buf: Vec<MaybeRelocatable> = felts
            .as_slice()
            .iter()
            .map(|x| MaybeRelocatable::from(x))
            .collect();

        for val in buf {
            args.push(val)
        }

        match cairo_runner.run_from_entrypoint_fuzz(
            entrypoint,
            args,
            true,
            &mut vm,
            &mut hint_processor,
        ) {
            Ok(()) => (),
            Err(_e) => {
                panic!("Fail to run input program")
            }
        };

        cairo_runner
            .relocate(&mut vm, false)
            .expect("Failed to relocate VM");
        let trace = vm.get_trace();
        let mut ret = Vec::<(u32, u32)>::new();
        for i in trace {
            ret.push((
                i.pc.try_into()
                    .expect("Failed to transform offset into u32"),
                i.fp.try_into()
                    .expect("Failed to transform offset into u32"),
            ))
        }

        return ExecutionResult {
            output: ret,
            reverted: false,
            new_state: StagedVMState::new_uninitialized(),
            additional_info: None,
        };
    }

    fn state_changed(&self) -> bool {
        todo!()
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        todo!()
    }
}
