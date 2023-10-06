use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::types::{as_u64, EVMAddress, EVMU256};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use bytes::Bytes;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm_interpreter::opcode::JUMPI;
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub struct Sha3TaintAnalysisCtx {
    pub dirty_memory: Vec<bool>,
    pub dirty_storage: HashMap<EVMU256, bool>,
    pub dirty_stack: Vec<bool>,
    pub input_data: Vec<bool>,
}

impl Sha3TaintAnalysisCtx {
    pub fn read_input(&self, start: usize, length: usize) -> Vec<bool> {
        let mut res = vec![false; length];
        for i in 0..length {
            res[i] = self.input_data[start + i];
        }
        res
    }
}

#[derive(Clone, Debug)]
pub struct Sha3TaintAnalysis {
    pub dirty_memory: Vec<bool>,
    pub dirty_storage: HashMap<EVMU256, bool>,
    pub dirty_stack: Vec<bool>,
    pub tainted_jumpi: HashSet<(EVMAddress, usize)>,

    pub ctxs: Vec<Sha3TaintAnalysisCtx>,
}

impl Sha3TaintAnalysis {
    pub fn new() -> Self {
        Self {
            dirty_memory: vec![],
            dirty_storage: HashMap::new(),
            dirty_stack: vec![],
            tainted_jumpi: HashSet::new(),
            ctxs: vec![],
        }
    }

    pub fn cleanup(&mut self) {
        self.dirty_memory.clear();
        self.dirty_storage.clear();
        self.dirty_stack.clear();
    }

    pub fn write_input(&self, start: usize, length: usize) -> Vec<bool> {
        let mut res = vec![false; length];
        for i in 0..length {
            res[i] = self.dirty_memory[start + i];
        }
        res
    }

    pub fn push_ctx(&mut self, interp: &mut Interpreter) {
        let (arg_offset, arg_len) = match unsafe { *interp.instruction_pointer } {
            0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
            0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
            _ => {
                panic!("not supported opcode");
            }
        };

        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;

        self.ctxs.push(Sha3TaintAnalysisCtx {
            input_data: self.write_input(arg_offset, arg_len),
            dirty_memory: self.dirty_memory.clone(),
            dirty_storage: self.dirty_storage.clone(),
            dirty_stack: self.dirty_stack.clone(),
        });

        self.cleanup();
    }

    pub fn pop_ctx(&mut self) {
        // println!("pop_ctx");
        let ctx = self.ctxs.pop().expect("ctxs is empty");
        self.dirty_memory = ctx.dirty_memory;
        self.dirty_storage = ctx.dirty_storage;
        self.dirty_stack = ctx.dirty_stack;
    }
}

impl<I, VS, S> Middleware<VS, I, S> for Sha3TaintAnalysis
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        _host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
        //
        // println!("on_step: {:?} with {:x}", interp.program_counter(), *interp.instruction_pointer);
        // println!("stack: {:?}", self.dirty_stack);
        // println!("origin: {:?}", interp.stack);

        macro_rules! pop_push {
            ($pop_cnt: expr,$push_cnt: expr) => {{
                let mut res = false;
                for _ in 0..$pop_cnt {
                    res |= self.dirty_stack.pop().expect("stack is empty");
                }
                for _ in 0..$push_cnt {
                    self.dirty_stack.push(res);
                }
            }};
        }

        macro_rules! stack_pop_n {
            ($pop_cnt: expr) => {
                for _ in 0..$pop_cnt {
                    self.dirty_stack.pop().expect("stack is empty");
                }
            };
        }

        macro_rules! push_false {
            () => {
                self.dirty_stack.push(false)
            };
        }

        macro_rules! ensure_size {
            ($t: expr, $size: expr) => {
                if $t.len() < $size {
                    $t.resize($size, false);
                }
            };
        }

        macro_rules! setup_mem {
            () => {{
                stack_pop_n!(3);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let len = as_u64(interp.stack.peek(2).expect("stack is empty")) as usize;
                ensure_size!(self.dirty_memory, mem_offset + len);
                self.dirty_memory[mem_offset..mem_offset + len]
                    .copy_from_slice(vec![false; len as usize].as_slice());
            }};
        }

        assert_eq!(interp.stack.len(), self.dirty_stack.len());

        match *interp.instruction_pointer {
            0x00 => {}
            0x01..=0x7 => {
                pop_push!(2, 1)
            }
            0x08..=0x09 => {
                pop_push!(3, 1)
            }
            0xa | 0x0b | 0x10..=0x14 => {
                pop_push!(2, 1);
            }
            0x15 => {
                pop_push!(1, 1);
            }
            0x16..=0x18 => {
                pop_push!(2, 1);
            }
            0x19 => {
                pop_push!(1, 1);
            }
            0x1a..=0x1d => {
                pop_push!(2, 1);
            }
            0x20 => {
                // sha3
                stack_pop_n!(2);
                self.dirty_stack.push(true);
            }
            0x30 => push_false!(),
            // BALANCE
            0x31 => pop_push!(1, 1),
            // ORIGIN
            0x32 => push_false!(),
            // CALLER
            0x33 => push_false!(),
            // CALLVALUE
            0x34 => push_false!(),
            // CALLDATALOAD
            0x35 => {
                self.dirty_stack.pop();
                if self.ctxs.len() > 0 {
                    let ctx = self.ctxs.last().unwrap();
                    let offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                    if offset == 0 {
                        push_false!()
                    } else {
                        let input = ctx.read_input(offset, 32).contains(&true);
                        // println!("CALLDATALOAD: {:x} -> {}", offset, input);
                        self.dirty_stack.push(input)
                    }
                } else {
                    push_false!()
                }
            }
            // CALLDATASIZE
            0x36 => push_false!(),
            // CALLDATACOPY
            0x37 => setup_mem!(),
            // CODESIZE
            0x38 => push_false!(),
            // CODECOPY
            0x39 => setup_mem!(),
            // GASPRICE
            0x3a => push_false!(),
            // EXTCODESIZE
            0x3b | 0x3f => {
                stack_pop_n!(1);
                self.dirty_stack.push(false);
            }
            // EXTCODECOPY
            0x3c => setup_mem!(),
            // RETURNDATASIZE
            0x3d => push_false!(),
            // RETURNDATACOPY
            0x3e => setup_mem!(),
            // COINBASE
            0x41..=0x48 => push_false!(),
            // POP
            0x50 => {
                self.dirty_stack.pop();
            }
            // MLOAD
            0x51 => {
                self.dirty_stack.pop();
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                ensure_size!(self.dirty_memory, mem_offset + 32);
                let is_dirty = self.dirty_memory[mem_offset..mem_offset + 32]
                    .iter()
                    .any(|x| *x);
                self.dirty_stack.push(is_dirty);
            }
            // MSTORE
            0x52 => {
                stack_pop_n!(1);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                ensure_size!(self.dirty_memory, mem_offset + 32);
                self.dirty_memory[mem_offset..mem_offset + 32]
                    .copy_from_slice(vec![is_dirty; 32].as_slice());
            }
            // MSTORE8
            0x53 => {
                stack_pop_n!(1);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                ensure_size!(self.dirty_memory, mem_offset + 1);
                self.dirty_memory[mem_offset] = is_dirty;
            }
            // SLOAD
            0x54 => {
                self.dirty_stack.pop();
                let key = interp.stack.peek(0).expect("stack is empty");
                let is_dirty = self.dirty_storage.get(&key).unwrap_or(&false);
                self.dirty_stack.push(*is_dirty);
            }
            // SSTORE
            0x55 => {
                self.dirty_stack.pop();
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                let key = interp.stack.peek(0).expect("stack is empty");
                self.dirty_storage.insert(key, is_dirty);
            }
            // JUMP
            0x56 => {
                self.dirty_stack.pop();
            }
            // JUMPI
            0x57 => {
                self.dirty_stack.pop();
                let v = self.dirty_stack.pop().expect("stack is empty");
                if v {
                    println!(
                        "new tainted jumpi: {:x} {:x}",
                        interp.contract.address,
                        interp.program_counter()
                    );
                    self.tainted_jumpi
                        .insert((interp.contract.address, interp.program_counter()));
                }
            }
            // PC
            0x58 | 0x59 | 0x5a => {
                push_false!();
            }
            // JUMPDEST
            0x5b => {}
            // PUSH
            0x5f..=0x7f => {
                push_false!();
            }
            // DUP
            0x80..=0x8f => {
                let _n = (*interp.instruction_pointer) - 0x80 + 1;
                self.dirty_stack
                    .push(self.dirty_stack[self.dirty_stack.len() - _n as usize]);
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 2;
                let _l = self.dirty_stack.len();
                let tmp = self.dirty_stack[_l - _n as usize];
                self.dirty_stack[_l - _n as usize] = self.dirty_stack[_l - 1];
                self.dirty_stack[_l - 1] = tmp;
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = (*interp.instruction_pointer) - 0xa0 + 2;
                stack_pop_n!(_n);
            }
            0xf0 => {
                stack_pop_n!(3);
                self.dirty_stack.push(false);
            }
            0xf1 => {
                stack_pop_n!(7);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xf2 => {
                stack_pop_n!(7);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xf3 => {
                stack_pop_n!(2);
            }
            0xf4 => {
                stack_pop_n!(6);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xf5 => {
                stack_pop_n!(4);
                self.dirty_stack.push(false);
            }
            0xfa => {
                stack_pop_n!(6);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xfd => {
                // stack_pop_n!(2);
            }
            0xfe => {
                // stack_pop_n!(1);
            }
            0xff => {
                // stack_pop_n!(1);
            }
            _ => panic!("unknown opcode: {:x}", *interp.instruction_pointer),
        }
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        _host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
        _by: &Bytes,
    ) {
        self.pop_ctx();
    }

    unsafe fn on_insert(
        &mut self,
        _bytecode: &mut Bytecode,
        _address: EVMAddress,
        _host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3TaintAnalysis
    }
}

#[derive(Debug)]
pub struct Sha3Bypass {
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
}

impl Sha3Bypass {
    pub fn new(sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>) -> Self {
        Self { sha3_taints }
    }
}

impl<I, VS, S> Middleware<VS, I, S> for Sha3Bypass
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
        if *interp.instruction_pointer == JUMPI {
            let jumpi = interp.program_counter();
            if self
                .sha3_taints
                .borrow()
                .tainted_jumpi
                .contains(&(interp.contract.address, jumpi))
            {
                let stack_len = interp.stack.len();
                interp.stack.data[stack_len - 2] =
                    EVMU256::from((jumpi + host.randomness[0] as usize) % 2);
            }
        }
    }

    unsafe fn on_insert(
        &mut self,
        _bytecode: &mut Bytecode,
        _address: EVMAddress,
        _host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3Bypass
    }
}
