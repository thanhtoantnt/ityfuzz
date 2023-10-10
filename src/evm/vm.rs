use crate::{
    evm::{
        bytecode_analyzer,
        host::{FuzzHost, COVERAGE_NOT_CHANGED, STATE_CHANGE},
        input::{ConciseEVMInput, EVMInputT},
        middlewares::middleware::Middleware,
        types::{EVMAddress, EVMU256},
    },
    generic_vm::{
        vm_executor::{ExecutionResult, GenericVM},
        vm_state::VMStateT,
    },
    input::{ConciseSerde, VMInputT},
    invoke_middlewares,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
    state_input::StagedVMState,
};
use bytes::Bytes;
use core::ops::Range;
use itertools::Itertools;
use libafl::{
    prelude::{HasMetadata, HasRand},
    state::{HasCorpus, State},
};
use revm_interpreter::{
    BytecodeLocked, CallContext, CallScheme, Contract, Gas,
    InstructionResult::{self, ControlLeak},
    Interpreter, Memory, Stack,
};
use revm_primitives::Bytecode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    any::Any,
    cell::RefCell,
    cmp::min,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
    sync::Arc,
};

pub const MEM_LIMIT: u64 = 10 * 1024;
const MAX_POST_EXECUTION: usize = 10;

/// Get the token context from the flashloan middleware,
/// which contains uniswap pairs of that token
#[macro_export]
macro_rules! get_token_ctx {
    ($flashloan_mid: expr, $token: expr) => {
        $flashloan_mid
            .flashloan_oracle
            .deref()
            .borrow()
            .known_tokens
            .get(&$token)
            .expect(format!("unknown token : {:?}", $token).as_str())
    };
}

/// Determine whether a call is successful
#[macro_export]
macro_rules! is_call_success {
    ($ret: expr) => {
        $ret == InstructionResult::Return
            || $ret == InstructionResult::Stop
            || $ret == ControlLeak
            || $ret == InstructionResult::SelfDestruct
    };
}

/// A post execution constraint
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Constraint {
    Caller(EVMAddress),
    Contract(EVMAddress),
    Value(EVMU256),
    NoLiquidation,
}

/// A post execution context
/// When control is leaked, we dump the current execution context. This context includes
/// all information needed to continue subsequent execution (e.g., stack, pc, memory, etc.)
/// Post execution context is attached to VM state if control is leaked.
///
/// When EVM input has `step` set to true, then we continue execution from the post
/// execution context available. If `step` is false, then we conduct reentrancy
/// (i.e., don't need to continue execution from the post execution context
/// but we execute the input directly
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SinglePostExecution {
    /// All continuation info
    /// Instruction pointer.
    pub program_counter: usize,
    /// Return is main control flag, it tell us if we should continue interpreter or break from it
    pub instruction_result: InstructionResult,
    /// Memory.
    pub memory: Memory,
    /// Stack.
    pub stack: Stack,
    /// Return value.
    pub return_range: Range<usize>,
    /// Is interpreter call static.
    pub is_static: bool,
    /// Contract information and invoking data
    pub input: Bytes,
    /// Bytecode contains contract code, size of original code, analysis with gas block and jump table.
    /// Note that current code is extended with push padding and STOP at end.
    pub code_address: EVMAddress,
    /// Contract address
    pub address: EVMAddress,
    /// Caller of the EVM.
    pub caller: EVMAddress,
    /// Value send to contract.
    pub value: EVMU256,

    /// Post execution related information
    /// Output Length
    pub output_len: usize,
    /// Output Offset
    pub output_offset: usize,
}

impl SinglePostExecution {
    pub fn hash(&self, hasher: &mut impl Hasher) {
        self.program_counter.hash(hasher);
        self.memory.data.hash(hasher);
        self.stack.data.hash(hasher);
        self.return_range.hash(hasher);
        self.is_static.hash(hasher);
        self.input.hash(hasher);
        self.code_address.hash(hasher);
        self.address.hash(hasher);
        self.caller.hash(hasher);
        self.value.hash(hasher);
        self.output_len.hash(hasher);
        self.output_offset.hash(hasher);
    }

    /// Convert the post execution context to revm [`CallContext`]
    fn get_call_ctx(&self) -> CallContext {
        CallContext {
            address: self.address,
            caller: self.caller,
            apparent_value: self.value,
            code_address: self.code_address,
            scheme: CallScheme::Call,
        }
    }

    fn get_interpreter(&self, bytecode: Arc<BytecodeLocked>) -> Interpreter {
        let contract =
            Contract::new_with_context_analyzed(self.input.clone(), bytecode, &self.get_call_ctx());

        let mut stack = Stack::new();
        for v in &self.stack.data {
            let _ = stack.push(v.clone());
        }

        Interpreter {
            instruction_pointer: unsafe { contract.bytecode.as_ptr().add(self.program_counter) },
            instruction_result: self.instruction_result,
            gas: Gas::new(0),
            memory: self.memory.clone(),
            stack,
            return_data_buffer: Bytes::new(),
            return_range: self.return_range.clone(),
            is_static: self.is_static,
            contract,
            #[cfg(feature = "memory_limit")]
            memory_limit: MEM_LIMIT,
        }
    }

    pub fn from_interp(interp: &Interpreter, (out_offset, out_len): (usize, usize)) -> Self {
        Self {
            program_counter: interp.program_counter(),
            instruction_result: interp.instruction_result,
            memory: interp.memory.clone(),
            stack: interp.stack.clone(),
            return_range: interp.return_range.clone(),
            is_static: interp.is_static,
            input: interp.contract.input.clone(),
            code_address: interp.contract.code_address,
            address: interp.contract.address,
            caller: interp.contract.caller,
            value: interp.contract.value,
            output_len: out_len,
            output_offset: out_offset,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostExecutionCtx {
    // constraints: Vec<Constraint>,
    pub pes: Vec<SinglePostExecution>,

    pub must_step: bool,
}

impl PostExecutionCtx {
    pub fn hash(&self, hasher: &mut impl Hasher) {
        for pe in &self.pes {
            pe.hash(hasher);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EVMState {
    /// State of the EVM, which is mapping of EVMU256 slot to EVMU256 value for each contract
    pub state: HashMap<EVMAddress, HashMap<EVMU256, EVMU256>>,

    /// Post execution context
    /// If control leak happens, we add the post execution context to the VM state,
    /// which contains all information needed to continue execution.
    ///
    /// There can be more than one [`PostExecutionCtx`] when the control is leaked again
    /// on the incomplete state (i.e., double+ reentrancy)
    post_execution: Vec<PostExecutionCtx>,

    #[serde(skip)]
    pub bug_hit: bool,
    /// selftdestruct() call in Solidity hit?
    #[serde(skip)]
    pub self_destruct: HashSet<(EVMAddress, usize)>,
    /// bug type call in solidity type
    #[serde(skip)]
    pub typed_bug: HashSet<(String, (EVMAddress, usize))>,
    #[serde(skip)]
    pub arbitrary_calls: HashSet<(EVMAddress, EVMAddress, usize)>,
}

impl Default for EVMState {
    fn default() -> Self {
        Self::new()
    }
}

impl VMStateT for EVMState {
    fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        for i in self.post_execution.iter() {
            i.hash(&mut s);
        }
        for i in self.state.iter().sorted_by_key(|k| k.0) {
            i.0 .0.hash(&mut s);
            for j in i.1.iter() {
                j.0.hash(&mut s);
                j.1.hash(&mut s);
            }
        }
        s.finish()
    }

    fn has_post_execution(&self) -> bool {
        self.post_execution.len() > 0
    }

    /// Get length needed for return data length of the call that leads to control leak
    fn get_post_execution_needed_len(&self) -> usize {
        self.post_execution
            .last()
            .unwrap()
            .pes
            .first()
            .unwrap()
            .output_len
    }

    /// Get the PC of last post execution context
    fn get_post_execution_pc(&self) -> usize {
        match self.post_execution.last() {
            Some(i) => i.pes.first().unwrap().program_counter,
            None => 0,
        }
    }

    /// Get amount of post execution context
    fn get_post_execution_len(&self) -> usize {
        self.post_execution.len()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        self.state.iter().all(|(k, v)| {
            other.state.get(k).map_or(false, |v2| {
                v.iter().all(|(k, v)| v2.get(k).map_or(false, |v2| v == v2))
            })
        })
    }
}

impl EVMState {
    /// Create a new EVM state, containing empty state, no post execution context
    pub(crate) fn new() -> Self {
        Self {
            state: HashMap::new(),
            post_execution: vec![],
            bug_hit: false,
            self_destruct: Default::default(),
            typed_bug: Default::default(),
            arbitrary_calls: Default::default(),
        }
    }

    /// Get all storage slots of a specific contract
    pub fn get(&self, address: &EVMAddress) -> Option<&HashMap<EVMU256, EVMU256>> {
        self.state.get(address)
    }

    /// Get all storage slots of a specific contract (mutable)
    pub fn get_mut(&mut self, address: &EVMAddress) -> Option<&mut HashMap<EVMU256, EVMU256>> {
        self.state.get_mut(address)
    }

    /// Insert all storage slots of a specific contract
    pub fn insert(&mut self, address: EVMAddress, storage: HashMap<EVMU256, EVMU256>) {
        self.state.insert(address, storage);
    }
}

/// Is current EVM execution fast call
pub static mut IS_FAST_CALL: bool = false;

/// Is current EVM execution fast call (static)
/// - Fast call is a call that does not change the state of the contract
pub static mut IS_FAST_CALL_STATIC: bool = false;

/// EVM executor, wrapper of revm
#[derive(Debug, Clone)]
pub struct EVMExecutor<I, S, VS, CI>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    /// Host providing the blockchain environment (e.g., writing/reading storage), needed by revm
    pub host: FuzzHost<VS, I, S>,
    /// [Depreciated] Deployer address
    deployer: EVMAddress,
    /// Known arbitrary (caller,pc)
    pub _known_arbitrary: HashSet<(EVMAddress, usize)>,
    phandom: PhantomData<(I, S, VS, CI)>,
}

pub fn is_reverted_or_control_leak(ret: &InstructionResult) -> bool {
    match *ret {
        InstructionResult::Return | InstructionResult::Stop | InstructionResult::SelfDestruct => {
            false
        }
        _ => true,
    }
}

/// Execution result that may have control leaked
/// Contains raw information of revm output and execution
#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    /// Output of the execution
    pub output: Bytes,
    /// The new state after execution
    pub new_state: EVMState,
    /// Program counter after execution
    pub pc: usize,
    /// Return value after execution
    pub ret: InstructionResult,
    /// Stack after execution
    pub stack: Vec<EVMU256>,
    /// Memory after execution
    pub memory: Vec<u8>,
}

impl<VS, I, S, CI> EVMExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasItyState<EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: Default + VMStateT + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
{
    /// Create a new EVM executor given a host and deployer address
    pub fn new(fuzz_host: FuzzHost<VS, I, S>, deployer: EVMAddress) -> Self {
        Self {
            host: fuzz_host,
            deployer,
            _known_arbitrary: Default::default(),
            phandom: PhantomData,
        }
    }

    /// Execute from a specific program counter and context
    ///
    /// `call_ctx` is the context of the call (e.g., caller address, callee address, etc.)
    /// `vm_state` is the VM state to execute on
    /// `data` is the input (function hash + serialized ABI args)
    /// `input` is the additional input information (e.g., access pattern, etc.)
    ///     If post execution context exists, then this is the return buffer of the call that leads
    ///     to control leak. This is like we are fuzzing the subsequent execution wrt the return
    ///     buffer of the control leak call.
    /// `post_exec` is the post execution context to use, if any
    ///     If `post_exec` is `None`, then the execution is from the beginning, otherwise it is from
    ///     the post execution context.
    pub fn execute_from_pc(
        &mut self,
        call_ctx: &CallContext,
        vm_state: &EVMState,
        data: Bytes,
        input: &I,
        post_exec: Option<SinglePostExecution>,
        state: &mut S,
        cleanup: bool,
    ) -> IntermediateExecutionResult {
        // Initial setups
        if cleanup {
            self.host.coverage_changed = false;
            self.host.bug_hit = false;
            self.host.current_typed_bug = vec![];
            self.host.jumpi_trace = 37;
            self.host.current_self_destructs = vec![];
            self.host.current_arbitrary_calls = vec![];
            // Initially, there is no state change
            unsafe {
                STATE_CHANGE = false;
            }
        }

        self.host.evmstate = vm_state.clone();
        self.host.env = input.get_vm_env().clone();
        self.host.access_pattern = input.get_access_pattern().clone();
        self.host.call_count = 0;
        self.host.randomness = input.get_randomness();
        let mut repeats = input.get_repeat();

        // Get the bytecode
        let bytecode = match self.host.code.get(&call_ctx.code_address) {
            Some(i) => i.clone(),
            None => {
                println!(
                    "no code @ {:?}, did you forget to deploy?",
                    call_ctx.code_address
                );
                return IntermediateExecutionResult {
                    output: Bytes::new(),
                    new_state: EVMState::default(),
                    pc: 0,
                    ret: InstructionResult::Revert,
                    stack: Default::default(),
                    memory: Default::default(),
                };
            }
        };

        // Create the interpreter
        let mut interp = if let Some(ref post_exec_ctx) = post_exec {
            // If there is a post execution context, then we need to create the interpreter from
            // the post execution context
            repeats = 1;
            {
                // setup the pc, memory, and stack as the post execution context
                let mut interp = post_exec_ctx.get_interpreter(bytecode);
                // set return buffer as the input
                // we remove the first 4 bytes because the first 4 bytes is the function hash (00000000 here)
                interp.return_data_buffer = data.slice(4..);
                let target_len = min(post_exec_ctx.output_len, interp.return_data_buffer.len());
                interp.memory.set(
                    post_exec_ctx.output_offset,
                    &interp.return_data_buffer[..target_len],
                );
                interp
            }
        } else {
            // if there is no post execution context, then we create the interpreter from the
            // beginning
            let call = Contract::new_with_context_analyzed(data, bytecode, call_ctx);
            Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT)
        };

        // Execute the contract for `repeats` times or until revert
        let mut r = InstructionResult::Stop;
        for _v in 0..repeats - 1 {
            // println!("repeat: {:?}", v);
            r = self.host.run_inspect(&mut interp, state);
            interp.stack.data.clear();
            interp.memory.data.clear();
            interp.instruction_pointer = interp.contract.bytecode.as_ptr();
            if !is_call_success!(r) {
                interp.return_range = 0..0;
                break;
            }
        }
        if is_call_success!(r) {
            r = self.host.run_inspect(&mut interp, state);
        }

        // Build the result
        let result = IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.evmstate.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };

        unsafe {
            if self.host.coverage_changed {
                COVERAGE_NOT_CHANGED = 0;
            } else {
                COVERAGE_NOT_CHANGED += 1;
            }
        }

        result
    }

    /// Execute a transaction, wrapper of [`EVMExecutor::execute_from_pc`]
    fn execute_abi(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, VS, Vec<u8>, CI> {
        // Get necessary info from input
        let vm_state = unsafe {
            input
                .get_state()
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone()
        };

        let r;
        let mut data = Bytes::from(input.to_bytes());
        // use direct data (mostly used for debugging) if there is no data
        if data.len() == 0 {
            data = Bytes::from(input.get_direct_data());
        }

        let mut cleanup = true;

        loop {
            // Execute the transaction
            let exec_res = {
                let caller = input.get_caller();
                let value = input.get_txn_value().unwrap_or(EVMU256::ZERO);
                let contract_address = input.get_contract();
                self.execute_from_pc(
                    &CallContext {
                        address: contract_address,
                        caller,
                        code_address: contract_address,
                        apparent_value: value,
                        scheme: CallScheme::Call,
                    },
                    &vm_state,
                    data,
                    input,
                    None,
                    state,
                    cleanup,
                )
            };
            let need_step = exec_res.new_state.post_execution.len() > 0
                && exec_res.new_state.post_execution.last().unwrap().must_step;
            if (exec_res.ret == InstructionResult::Return
                || exec_res.ret == InstructionResult::Stop)
                && need_step
            {
                data = Bytes::from([vec![0; 4], exec_res.output.to_vec()].concat());
                // we dont need to clean up bug info and state info
                cleanup = false;
            } else {
                r = Some(exec_res);
                break;
            }
        }
        let mut r = r.unwrap();
        match r.ret {
            ControlLeak | InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) => {
                if r.new_state.post_execution.len() + 1 > MAX_POST_EXECUTION {
                    return ExecutionResult {
                        output: r.output.to_vec(),
                        reverted: true,
                        new_state: StagedVMState::new_uninitialized(),
                        additional_info: None,
                    };
                }
                let leak_ctx = self.host.leak_ctx.clone();
                r.new_state.post_execution.push(PostExecutionCtx {
                    pes: leak_ctx,
                    must_step: match r.ret {
                        ControlLeak => false,
                        InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) => true,
                        _ => unreachable!(),
                    },
                });
            }
            _ => {}
        }

        r.new_state.typed_bug = HashSet::from_iter(
            vm_state
                .typed_bug
                .iter()
                .cloned()
                .chain(self.host.current_typed_bug.iter().cloned()),
        );
        r.new_state.self_destruct = HashSet::from_iter(
            vm_state
                .self_destruct
                .iter()
                .cloned()
                .chain(self.host.current_self_destructs.iter().cloned()),
        );
        r.new_state.arbitrary_calls = HashSet::from_iter(
            vm_state
                .arbitrary_calls
                .iter()
                .cloned()
                .chain(self.host.current_arbitrary_calls.iter().cloned()),
        );

        // println!("r.ret: {:?}", r.ret);

        unsafe {
            ExecutionResult {
                output: r.output.to_vec(),
                reverted: match r.ret {
                    InstructionResult::Return
                    | InstructionResult::Stop
                    | InstructionResult::ControlLeak
                    | InstructionResult::SelfDestruct
                    | InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) => false,
                    _ => true,
                },
                new_state: StagedVMState::new_with_state(
                    VMStateT::as_any(&mut r.new_state)
                        .downcast_ref_unchecked::<VS>()
                        .clone(),
                ),
                additional_info: if r.ret == ControlLeak {
                    Some(vec![self.host.call_count as u8])
                } else {
                    None
                },
            }
        }
    }

    pub fn reexecute_with_middleware(
        &mut self,
        input: &I,
        state: &mut S,
        middleware: Rc<RefCell<dyn Middleware<VS, I, S>>>,
    ) {
        self.host.add_middlewares(middleware.clone());
        self.execute(input, state);
        self.host.remove_middlewares(middleware);
    }
}

pub static mut IN_DEPLOY: bool = false;

impl<VS, I, S, CI> GenericVM<VS, Bytecode, Bytes, EVMAddress, Vec<u8>, I, S, CI>
    for EVMExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasItyState<EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
{
    /// Deploy a contract
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: EVMAddress,
        state: &mut S,
    ) -> Option<EVMAddress> {
        let deployer = Contract::new(
            constructor_args.unwrap_or(Bytes::new()),
            code,
            deployed_address,
            deployed_address,
            self.deployer,
            EVMU256::from(0),
        );
        // disable middleware for deployment
        unsafe {
            IN_DEPLOY = true;
        }
        let mut interp =
            Interpreter::new_with_memory_limit(deployer, 1e10 as u64, false, MEM_LIMIT);
        let mut dummy_state = S::default();
        let r = self.host.run_inspect(&mut interp, &mut dummy_state);
        unsafe {
            IN_DEPLOY = false;
        }
        if r != InstructionResult::Return {
            println!("deploy failed: {:?}", r);
            return None;
        }
        println!(
            "deployer = 0x{} contract = {:?}",
            hex::encode(self.deployer),
            hex::encode(interp.return_value())
        );
        let mut contract_code = Bytecode::new_raw(interp.return_value());
        bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
        unsafe {
            invoke_middlewares!(
                &mut contract_code,
                deployed_address,
                &mut self.host,
                state,
                on_insert
            );
        }
        self.host.set_code(deployed_address, contract_code, state);
        Some(deployed_address)
    }

    fn execute(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, VS, Vec<u8>, CI> {
        self.execute_abi(input, state)
    }

    fn state_changed(&self) -> bool {
        unsafe { STATE_CHANGE }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
