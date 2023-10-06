use bytes::Bytes;

use crate::evm::abi::BoxedABI;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::middleware::MiddlewareType::Concolic;
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};

use crate::evm::host::FuzzHost;
use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};

use libafl::prelude::{HasMetadata, Input};

use libafl::state::{HasCorpus, State};

use revm_interpreter::Interpreter;
use revm_primitives::{Bytecode, HashMap};

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

use crate::evm::concolic::concolic_stage::ConcolicPrioritizationMetadata;
use crate::evm::concolic::expr::{simplify, ConcolicOp, Expr};
use crate::evm::types::{as_u64, is_zero, EVMAddress, EVMU256};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

pub static mut CONCOLIC_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Field {
    Caller,
    CallDataValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub input: Vec<u8>,
    pub caller: EVMAddress,
    pub value: EVMU256,
    pub fields: Vec<Field>,
}

impl Solution {
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("(input: {:?}, ", hex::encode(&self.input)));
        s.push_str(&format!("caller: {:?}, ", self.caller));
        s.push_str(&format!("value: {})", self.value));
        s
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolicMemory {
    /// Memory is a vector of bytes, each byte is a symbolic value
    pub memory: Vec<Option<Box<Expr>>>,
    // pub memory_32: Vec<Option<Box<Expr>>>,
}

impl SymbolicMemory {
    pub fn new() -> Self {
        Self {
            memory: vec![],
            // memory_32: vec![],
        }
    }

    pub fn insert_256(&mut self, idx: EVMU256, val: Box<Expr>) {
        let idx = idx.as_limbs()[0] as usize;
        if idx + 32 >= self.memory.len() {
            self.memory.resize(idx + 32 + 1, None);
            // self.memory_32.resize(idx / 32 + 1, None);
        }

        // if idx % 32 == 0 {
        //     self.memory_32[idx / 32] = Some(val.clone());
        // }

        for i in 0..32 {
            let i_u32 = i as u32;
            self.memory[idx + i] = Some(Box::new(Expr {
                lhs: Some(val.clone()),
                rhs: None,
                op: ConcolicOp::SELECT(256 - i_u32 * 8 - 1, 256 - i_u32 * 8 - 7 - 1),
            }));
        }
    }

    pub fn insert_8(&mut self, idx: EVMU256, val: Box<Expr>) {
        // TODO: use SELECT instead of concrete value
        let idx = idx.as_limbs()[0] as usize;
        if idx >= self.memory.len() {
            self.memory.resize(idx + 1, None);
        }

        println!("insert_8: idx: {}, val: {:?}", idx, val);
        todo!("insert_8");
        // self.memory[idx] = Some(Box::new(Expr {
        //     lhs: Some(val.clone()),
        //     rhs: None,
        //     op: ConcolicOp::SELECT(31 - i_u32*8, 24 - i_u32*8),
        // }));
    }

    pub fn get_256(&self, idx: EVMU256) -> Option<Box<Expr>> {
        let idx = idx.as_limbs()[0] as usize;
        if idx >= self.memory.len() {
            return None;
        }

        // if idx % 32 == 0 {
        //     return self.memory_32[idx / 32].clone();
        // }

        let mut all_bytes = if let Some(by) = self.memory[idx].clone() {
            by
        } else {
            Box::new(Expr {
                lhs: None,
                rhs: None,
                op: ConcolicOp::CONSTBYTE(0),
            })
        };
        for i in 1..32 {
            all_bytes = Box::new(Expr {
                lhs: Some(all_bytes),
                rhs: if let Some(by) = self.memory[idx + i].clone() {
                    Some(by)
                } else {
                    Some(Box::new(Expr {
                        lhs: None,
                        rhs: None,
                        op: ConcolicOp::CONSTBYTE(0),
                    }))
                },
                op: ConcolicOp::CONCAT,
            });
        }

        Some(simplify(all_bytes))
    }

    pub fn get_slice(&mut self, idx: EVMU256, len: EVMU256) -> Vec<Box<Expr>> {
        let idx = idx.as_limbs()[0] as usize;
        let len = len.as_limbs()[0] as usize;

        if idx + len >= self.memory.len() {
            self.memory.resize(idx + len + 1, None);
        }

        let mut result = vec![];

        for i in idx..(idx + len) {
            if i >= self.memory.len() {
                result.push(Box::new(Expr {
                    lhs: None,
                    rhs: None,
                    op: ConcolicOp::CONSTBYTE(0),
                }));
            } else {
                result.push(if let Some(by) = self.memory[i].clone() {
                    by
                } else {
                    Box::new(Expr {
                        lhs: None,
                        rhs: None,
                        op: ConcolicOp::CONSTBYTE(0),
                    })
                });
            }
        }
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConcolicCallCtx {
    pub symbolic_stack: Vec<Option<Box<Expr>>>,
    pub symbolic_memory: SymbolicMemory,
    pub symbolic_state: HashMap<EVMU256, Option<Box<Expr>>>,

    // seperated by 32 bytes
    pub input_bytes: Vec<Box<Expr>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConcolicHost<I, VS> {
    pub symbolic_stack: Vec<Option<Box<Expr>>>,
    pub symbolic_memory: SymbolicMemory,
    pub symbolic_state: HashMap<EVMU256, Option<Box<Expr>>>,
    pub input_bytes: Vec<Box<Expr>>,
    pub constraints: Vec<Box<Expr>>,
    pub testcase_ref: Arc<EVMInput>,

    pub ctxs: Vec<ConcolicCallCtx>,
    pub phantom: PhantomData<(I, VS)>,
}

impl<I, VS> ConcolicHost<I, VS> {
    pub fn new(testcase_ref: Arc<EVMInput>) -> Self {
        Self {
            symbolic_stack: Vec::new(),
            symbolic_memory: SymbolicMemory::new(),
            symbolic_state: Default::default(),
            input_bytes: Self::construct_input_from_abi(
                testcase_ref.get_data_abi().expect("data abi not found"),
            ),
            constraints: vec![],
            testcase_ref,
            phantom: Default::default(),
            ctxs: vec![],
        }
    }

    pub fn pop_ctx(&mut self) {
        let ctx = self.ctxs.pop();
        if let Some(ctx) = ctx {
            self.symbolic_stack = ctx.symbolic_stack;
            self.symbolic_memory = ctx.symbolic_memory;
            self.symbolic_state = ctx.symbolic_state;
        } else {
            panic!("pop_ctx: ctx is empty");
        }
    }

    pub fn push_ctx(&mut self, interp: &mut Interpreter) {
        // interp.stack.data()[interp.stack.len() - 1 - $idx]
        let (arg_offset, arg_len) = match unsafe { *interp.instruction_pointer } {
            0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
            0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
            _ => {
                panic!("not supported opcode");
            }
        };

        let ctx = ConcolicCallCtx {
            symbolic_stack: self.symbolic_stack.clone(),
            symbolic_memory: self.symbolic_memory.clone(),
            symbolic_state: self.symbolic_state.clone(),
            input_bytes: {
                let by = self.symbolic_memory.get_slice(arg_offset, arg_len);
                by
            },
        };
        self.ctxs.push(ctx);

        self.symbolic_stack = vec![];
        self.symbolic_memory = SymbolicMemory::new();
        self.symbolic_state = Default::default();
    }

    fn construct_input_from_abi(vm_input: BoxedABI) -> Vec<Box<Expr>> {
        let res = vm_input.get_concolic();
        // println!("[concolic] construct_input_from_abi: {:?}", res);
        res
    }

    pub fn get_input_slice_from_ctx(&self, idx: usize, length: usize) -> Box<Expr> {
        let data = self.ctxs.last().expect("no ctx").input_bytes.clone();
        let mut bytes = data[idx].clone();
        for i in idx + 1..idx + length {
            if i >= data.len() {
                bytes = bytes.concat(Expr::const_byte(0));
            } else {
                bytes = bytes.concat(data[i].clone());
            }
        }
        simplify(bytes)
    }
}

impl<I, VS, S> Middleware<VS, I, S> for ConcolicHost<I, VS>
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
        state: &mut S,
    ) {
        macro_rules! fast_peek {
            ($idx:expr) => {
                interp.stack.data()[interp.stack.len() - 1 - $idx]
            };
        }

        macro_rules! stack_bv {
            ($idx:expr) => {{
                let real_loc_sym = self.symbolic_stack.len() - 1 - $idx;
                match self.symbolic_stack[real_loc_sym].borrow() {
                    Some(bv) => bv.clone(),
                    None => {
                        let u256 = fast_peek!($idx);
                        Box::new(Expr {
                            lhs: None,
                            rhs: None,
                            op: ConcolicOp::EVMU256(u256),
                        })
                    }
                }
            }};
        }

        macro_rules! concrete_eval {
            ($in_cnt: expr, $out_cnt: expr) => {{
                // println!("[concolic] concrete_eval: {} {}", $in_cnt, $out_cnt);
                for _ in 0..$in_cnt {
                    self.symbolic_stack.pop();
                }
                vec![None; $out_cnt]
            }};
        }

        macro_rules! concrete_eval_with_action {
            ($in_cnt: expr, $out_cnt: expr, $pp: ident) => {{
                // println!("[concolic] concrete_eval: {} {}", $in_cnt, $out_cnt);
                for _ in 0..$in_cnt {
                    self.symbolic_stack.pop();
                }
                for _ in 0..$out_cnt {
                    self.symbolic_stack.push(None);
                }
                self.$pp(interp);
                vec![]
            }};
        }

        let solutions = vec![];

        // if self.ctxs.len() > 0 {
        //     return;
        // }

        // TODO: Figure out the corresponding MiddlewareOp to add
        // We may need coverage map here to decide whether to add a new input to the
        // corpus or not.
        // println!("[concolic] on_step @ {:x}: {:x}", interp.program_counter(), *interp.instruction_pointer);
        // println!("[concolic] stack: {:?}", interp.stack.len());
        // println!("[concolic] symbolic_stack: {:?}", self.symbolic_stack.len());

        // let mut max_depth = 0;
        // let mut max_ref = None;
        // for s in &self.symbolic_stack {
        //     if let Some(bv) = s {
        //         let depth = bv.depth();
        //         if depth > max_depth {
        //             max_depth = depth;
        //             max_ref = Some(bv);
        //         }
        //     }
        // }
        //
        // println!("max_depth: {} for {:?}", max_depth, max_ref.map(|x| x.pretty_print_str()));
        // println!("max_depth simpl: {:?} for {:?}", max_ref.map(|x| simplify(x.clone()).depth()), max_ref.map(|x| simplify(x.clone()).pretty_print_str()));
        #[cfg(feature = "z3_debug")]
        {
            println!(
                "[concolic] on_step @ {:x}: {:x}",
                interp.program_counter(),
                *interp.instruction_pointer
            );
            println!("[concolic] stack: {:?}", interp.stack);
            println!("[concolic] symbolic_stack: {:?}", self.symbolic_stack);
            for idx in 0..interp.stack.len() {
                let real = interp.stack.data[idx].clone();
                let sym = self.symbolic_stack[idx].clone();
                if sym.is_some() {
                    match sym.unwrap().op {
                        ConcolicOp::EVMU256(v) => {
                            assert_eq!(real, v);
                        }
                        _ => {}
                    }
                }
            }
            assert_eq!(interp.stack.len(), self.symbolic_stack.len());
        }

        let bv: Vec<Option<Box<Expr>>> = match *interp.instruction_pointer {
            // ADD
            0x01 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MUL
            0x02 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SUB
            0x03 => {
                let res = Some(stack_bv!(0).sub(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // DIV - is this signed?
            0x04 => {
                let res = Some(stack_bv!(0).div(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SDIV
            0x05 => {
                let res = Some(stack_bv!(0).bvsdiv(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MOD
            0x06 => {
                let res = Some(stack_bv!(0).bvurem(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SMOD
            0x07 => {
                let res = Some(stack_bv!(0).bvsmod(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ADDMOD
            0x08 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)).bvsmod(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MULMOD
            0x09 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)).bvsmod(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EXP - fallback to concrete due to poor Z3 performance support
            0x0a => {
                concrete_eval!(2, 1)
            }
            // SIGNEXTEND - FIXME: need to check
            0x0b => {
                concrete_eval!(2, 1)
            }
            // LT
            0x10 => {
                let res = Some(stack_bv!(0).bvult(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // GT
            0x11 => {
                let res = Some(stack_bv!(0).bvugt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SLT
            0x12 => {
                let res = Some(stack_bv!(0).bvslt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SGT
            0x13 => {
                let res = Some(stack_bv!(0).bvsgt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EQ
            0x14 => {
                let res = Some(stack_bv!(0).equal(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ISZERO
            0x15 => {
                let res = Some(stack_bv!(0).equal(Box::new(Expr {
                    lhs: None,
                    rhs: None,
                    op: ConcolicOp::EVMU256(EVMU256::from(0)),
                })));
                self.symbolic_stack.pop();
                vec![res]
            }
            // AND
            0x16 => {
                let res = Some(stack_bv!(0).bvand(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // OR
            0x17 => {
                let res = Some(stack_bv!(0).bvor(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // XOR
            0x18 => {
                let res = Some(stack_bv!(0).bvxor(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // NOT
            0x19 => {
                let res = Some(stack_bv!(0).bvnot());
                self.symbolic_stack.pop();
                vec![res]
            }
            // BYTE
            // FIXME: support this
            0x1a => {
                concrete_eval!(2, 1)
            }
            // SHL
            0x1b => {
                let res = Some(stack_bv!(1).bvshl(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHR
            0x1c => {
                let res = Some(stack_bv!(1).bvlshr(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SAR
            0x1d => {
                let res = Some(stack_bv!(1).bvsar(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHA3
            0x20 => {
                concrete_eval!(2, 1)
            }
            // ADDRESS
            0x30 => {
                vec![None]
            }
            // BALANCE
            // TODO: need to get value from a hashmap
            0x31 => {
                concrete_eval!(1, 1)
            }
            // ORIGIN
            0x32 => {
                vec![None]
            }
            // CALLER
            0x33 => {
                // println!("CALLER @ pc : {:x}", interp.program_counter());
                if self.ctxs.len() > 0 {
                    // use concrete caller when inside a call
                    vec![None]
                } else {
                    vec![Some(Expr::new_caller())]
                }
            }
            // CALLVALUE
            0x34 => {
                if self.ctxs.len() > 0 {
                    // use concrete caller when inside a call
                    vec![None]
                } else {
                    vec![Some(Expr::new_callvalue())]
                }
            }
            // CALLDATALOAD
            0x35 => {
                let offset = interp.stack.peek(0).unwrap();
                self.symbolic_stack.pop();
                if self.ctxs.len() > 0 {
                    let offset_usize = as_u64(offset) as usize;
                    #[cfg(feature = "z3_debug")]
                    {
                        println!(
                            "CALLDATALOAD: {:?}",
                            self.get_input_slice_from_ctx(offset_usize, 32)
                        );
                        self.get_input_slice_from_ctx(offset_usize, 32)
                            .pretty_print();
                    }
                    vec![Some(self.get_input_slice_from_ctx(offset_usize, 32))]
                } else {
                    vec![Some(Expr::new_sliced_input(offset))]
                }
            }
            // CALLDATASIZE
            0x36 => {
                vec![None]
            }
            // CALLDATACOPY
            0x37 => {
                concrete_eval!(3, 0)
            }
            // CODESIZE
            0x38 => {
                vec![None]
            }
            // CODECOPY
            0x39 => {
                concrete_eval!(3, 0)
            }
            // GASPRICE
            0x3a => {
                vec![None]
            }
            // EXTCODESIZE
            0x3b => {
                concrete_eval!(1, 1)
            }
            // EXTCODECOPY
            0x3c => {
                concrete_eval!(4, 0)
            }
            // RETURNDATASIZE
            0x3d => {
                vec![None]
            }
            // RETURNDATACOPY
            0x3e => {
                concrete_eval!(3, 0)
            }
            // EXTCODEHASH
            0x3f => {
                concrete_eval!(1, 1)
            }
            // BLOCKHASH
            0x40 => {
                concrete_eval!(1, 1)
            }
            // COINBASE
            0x41 => {
                vec![None]
            }
            // TIMESTAMP
            0x42 => {
                vec![None]
            }
            // NUMBER
            0x43 => {
                vec![None]
            }
            // PREVRANDAO
            0x44 => {
                vec![None]
            }
            // GASLIMIT
            0x45 => {
                vec![None]
            }
            // CHAINID
            0x46 => {
                vec![None]
            }
            // SELFBALANCE
            0x47 => {
                vec![None]
            }
            // BASEFEE
            0x48 => {
                vec![None]
            }
            // POP
            0x50 => {
                self.symbolic_stack.pop();
                vec![]
            }
            // MLOAD
            0x51 => {
                // println!("[concolic] MLOAD: {:?}", self.symbolic_stack);
                let offset = fast_peek!(0);
                self.symbolic_stack.pop();
                vec![self.symbolic_memory.get_256(offset)]
            }
            // MSTORE
            0x52 => {
                let offset = fast_peek!(0);
                let value = stack_bv!(1);
                self.symbolic_memory.insert_256(offset, value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // MSTORE8
            0x53 => {
                let offset = fast_peek!(0);
                let value = stack_bv!(1);
                self.symbolic_memory.insert_8(offset, value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // SLOAD
            0x54 => {
                self.symbolic_stack.pop();
                let key = fast_peek!(0);
                vec![match self.symbolic_state.get(&key) {
                    Some(v) => v.clone(),
                    None => None,
                }]
            }
            // SSTORE
            0x55 => {
                let key = fast_peek!(1);
                let value = stack_bv!(0);
                self.symbolic_state.insert(key, Some(value));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // JUMP
            0x56 => {
                concrete_eval!(1, 0)
            }
            // JUMPI
            0x57 => {
                // println!("{:?}", interp.stack);
                // println!("{:?}", self.symbolic_stack);
                // jump dest in concolic solving mode is the opposite of the concrete
                let br = is_zero(fast_peek!(1));

                let real_path_constraint = if br {
                    // path_condition = false
                    stack_bv!(1).lnot()
                } else {
                    // path_condition = true
                    stack_bv!(1)
                };

                // jumping only happens if the second element is false
                if !real_path_constraint.is_concrete() {
                    self.constraints.push(real_path_constraint);
                }
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // PC
            0x58 => {
                vec![None]
            }
            // MSIZE
            0x59 => {
                vec![None]
            }
            // GAS
            0x5a => {
                vec![None]
            }
            // JUMPDEST
            0x5b => {
                vec![]
            }
            // PUSH
            0x60..=0x7f => {
                // push n bytes into stack
                // Concolic push n bytes is equivalent to concrete push, because the bytes
                // being pushed are always concrete, we can just push None to the stack
                // and 'fallthrough' to concrete values later
                vec![None]
            }
            // DUP
            0x80..=0x8f => {
                let _n = (*interp.instruction_pointer) - 0x80;
                vec![Some(stack_bv!(usize::from(_n)).clone())]
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 1;
                let swapper = stack_bv!(usize::from(_n));
                let swappee = stack_bv!(0);
                let symbolic_stack_len = self.symbolic_stack.len();
                self.symbolic_stack[symbolic_stack_len - 1] = Some(swapper);
                self.symbolic_stack[symbolic_stack_len - usize::from(_n) - 1] = Some(swappee);
                vec![]
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = (*interp.instruction_pointer) - 0xa0;
                concrete_eval!(_n + 2, 0)
            }
            // CREATE
            0xf0 => {
                concrete_eval!(3, 1)
            }
            // CALL
            0xf1 => {
                concrete_eval_with_action!(7, 1, push_ctx)
            }
            // CALLCODE
            0xf2 => {
                concrete_eval_with_action!(7, 1, push_ctx)
            }
            // RETURN
            0xf3 => {
                vec![]
            }
            // DELEGATECALL
            0xf4 => {
                concrete_eval_with_action!(6, 1, push_ctx)
            }
            // CREATE2
            0xf5 => {
                concrete_eval!(4, 1)
            }
            // STATICCALL
            0xfa => {
                concrete_eval_with_action!(6, 1, push_ctx)
            }
            // REVERT
            0xfd => {
                concrete_eval!(2, 0)
            }
            // INVALID
            0xfe => {
                vec![]
            }
            // SELFDESTRUCT
            0xff => {
                concrete_eval!(1, 0)
            }
            // STOP
            0x00 => {
                vec![]
            }
            _ => {
                panic!("Unsupported opcode: {:?}", *interp.instruction_pointer);
            }
        };
        // println!("[concolic] adding bv to stack {:?}", bv);
        for v in bv {
            if v.is_some() && v.as_ref().unwrap().is_concrete() {
                self.symbolic_stack.push(None);
            } else {
                self.symbolic_stack.push(v);
            }
        }

        // let input = state
        //     .corpus()
        //     .get(state.get_current_input_idx())
        //     .unwrap()
        //     .borrow_mut()
        //     .load_input()
        //     .expect("Failed loading input")
        //     .clone();

        if solutions.len() > 0 {
            let meta = state
                .metadata_mut()
                .get_mut::<ConcolicPrioritizationMetadata>()
                .expect("Failed to get metadata");
            for solution in solutions {
                meta.solutions.push((solution, self.testcase_ref.clone()));
            }
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
        Concolic
    }
}
