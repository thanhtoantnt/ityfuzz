use super::{
    types::CairoAddress,
    vm::{CairoState, HasCairoInput},
};
use crate::{
    generic_vm::vm_executor::ExecutionResult,
    input::{ConciseSerde, VMInputT},
    state::HasCaller,
    state_input::StagedVMState,
};
use felt::Felt252;
use libafl::{
    prelude::{Input, MutationResult},
    state::{HasMaxSize, HasMetadata, HasRand, State},
};
use serde::{Deserialize, Serialize};

use std::fmt::Debug;

#[derive(Serialize, Deserialize, Clone)]
pub struct CairoInput {
    pub repeat: usize,

    pub func_name: String,

    pub felts: Vec<Felt252>,

    /// Staged VM state
    #[serde(skip_deserializing)]
    pub sstate: StagedVMState<CairoAddress, CairoState, ConciseCairoInput>,

    /// Staged VM state index in the corpus
    #[serde(skip_deserializing)]
    pub sstate_idx: usize,

    /// Maximum size to allow inputs to expand to
    pub max_input_size: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConciseCairoInput {
    pub felts: Vec<Felt252>,
}

impl ConciseCairoInput {
    pub fn from_input<I, Out>(
        input: &I,
        _execution_result: &ExecutionResult<CairoAddress, CairoState, Out, ConciseCairoInput>,
    ) -> Self
    where
        I: VMInputT<CairoState, CairoAddress, ConciseCairoInput> + HasCairoInput,
        Out: Default,
    {
        Self {
            felts: input.get_felts(),
        }
    }
}
impl ConciseSerde for ConciseCairoInput {
    fn serialize_concise(&self) -> Vec<u8> {
        todo!()
    }

    fn deserialize_concise(_data: &[u8]) -> Self {
        todo!()
    }

    fn serialize_string(&self) -> String {
        todo!()
    }
}

macro_rules! byte_corruptor {
    ($func:ident, $corrupt:expr) => {
        /// Corrupt a byte in the input
        fn $func(&mut self) {
            // Only corrupt a byte if there are bytes present
            if !self.input.is_empty() {
                // Pick a random byte offset
                let offset = self.rand_offset();

                // Perform the corruption
                self.input[offset] = ($corrupt)(self, self.input[offset].clone()).into();
            }
        }
    };
}

struct Rng {
    seed: u64,
    exp_disabled: bool,
}

impl Rng {
    #[inline]
    fn next(&mut self) -> u64 {
        let val = self.seed;
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 17;
        self.seed ^= self.seed << 43;
        val
    }

    #[inline]
    fn rand(&mut self, min: usize, max: usize) -> usize {
        assert!(max >= min, "Bad range specified for rand()");
        if min == max {
            return min;
        }
        if min == 0 && max == core::usize::MAX {
            return self.next() as usize;
        }
        min + (self.next() as usize % (max - min + 1))
    }

    #[inline]
    fn rand_exp(&mut self, min: usize, max: usize) -> usize {
        if self.exp_disabled {
            return self.rand(min, max);
        }

        if self.rand(0, 1) == 0 {
            self.rand(min, max)
        } else {
            let x = self.rand(min, max);
            self.rand(min, x)
        }
    }
}

pub struct Strategy {
    pub input: Vec<Felt252>,
    pub accessed: Vec<usize>,
    rng: Rng,
    max_input_size: usize,
}

impl Strategy {
    byte_corruptor!(inc_byte, |_: &mut Self, x: Felt252| -> Felt252 {
        x + Felt252::from(1)
    });

    /// Generate a random offset, see `rand_offset_int` for more info
    fn rand_offset(&mut self) -> usize {
        self.rand_offset_int(false)
    }

    fn rand_offset_int(&mut self, plus_one: bool) -> usize {
        if !self.accessed.is_empty() {
            self.accessed[self.rng.rand_exp(0, self.accessed.len() - 1)]
        } else if !self.input.is_empty() {
            self.rng
                .rand_exp(0, self.input.len() - (!plus_one) as usize)
        } else {
            0
        }
    }

    pub fn random_insert(&mut self) {
        let offset = self.rand_offset_int(true);
        let amount = self.rng.rand_exp(0, self.input.len() - offset);
        let amount = core::cmp::min(amount, self.max_input_size - self.input.len());
        let rng = &mut self.rng;
        self.input.splice(
            offset..offset,
            (0..amount).map(|_| Felt252::from(rng.rand(0, 255))),
        );
    }

    byte_corruptor!(dec_byte, |_: &mut Self, x: Felt252| -> Felt252 {
        x - Felt252::from(1)
    });

    byte_corruptor!(neg_byte, |_: &mut Self, x: Felt252| -> Felt252 { -x });

    fn add_sub(&mut self) {
        if self.input.is_empty() {
            return;
        }

        let offset = self.rand_offset();
        let remain = self.input.len() - offset;
        let intsize = match remain {
            1..=1 => 1,
            2..=3 => 1 << self.rng.rand(0, 1),
            4..=7 => 1 << self.rng.rand(0, 2),
            8..=core::usize::MAX => 1 << self.rng.rand(0, 3),
            _ => unreachable!(),
        };

        let range = match intsize {
            1 => 16,
            2 => 4096,
            4 => 1024 * 1024,
            8 => 256 * 1024 * 1024,
            _ => unreachable!(),
        };

        let delta = self.rng.rand(0, range * 2) as i32 - range as i32;

        /// Macro to mutate bytes in the input as a `$ty`
        macro_rules! mutate {
            ($ty:ty) => {{
                // Interpret the `offset` as a `$ty`
                let tmp = self.input[offset].clone();

                // Apply the delta, interpreting the bytes as a random
                // endianness
                let tmp = if self.rng.rand(0, 1) == 0 {
                    (Felt252::from(delta) + Felt252::from(tmp))
                } else {
                    //tmp.swap_bytes().wrapping_add(delta as $ty).swap_bytes()
                    Felt252::from(delta)
                };

                // Write the new value out to the input
                self.input[offset] += Felt252::from(tmp);
            }};
        }

        match intsize {
            1 => mutate!(u8),
            2 => mutate!(u16),
            4 => mutate!(u32),
            8 => mutate!(u64),
            16 => mutate!(Felt252),
            _ => unreachable!(),
        };
    }

    fn swap(&mut self) {
        if self.input.is_empty() {
            return;
        }
        let src = self.rand_offset();
        let srcrem = self.input.len() - src;
        let dst = self.rand_offset();
        let dstrem = self.input.len() - dst;
        let len = self.rng.rand_exp(1, core::cmp::min(srcrem, dstrem));
        Self::swap_ranges(&mut self.input, src, dst, len);
    }

    fn swap_ranges(vec: &mut [Felt252], mut offset1: usize, mut offset2: usize, mut len: usize) {
        if offset1 < offset2 && offset1 + len >= offset2 {
            let tail = offset2 - offset1;
            for ii in (tail..len).rev() {
                vec[offset2 + ii] = vec[offset1 + ii].clone();
            }
            len = tail;
        } else if offset2 < offset1 && offset2 + len >= offset1 {
            let head = len - (offset1 - offset2);
            for ii in 0..head {
                vec[offset2 + ii] = vec[offset1 + ii].clone();
            }
            offset1 += head;
            offset2 += head;
            len -= head;
        }

        for ii in 0..len {
            vec.swap(offset1 + ii, offset2 + ii);
        }
    }

    const STRATEGIES: &[fn(&mut Strategy)] = &[
        Strategy::inc_byte,
        Strategy::dec_byte,
        Strategy::neg_byte,
        Strategy::random_insert,
        Strategy::add_sub,
        Strategy::swap,
    ];

    pub fn mutate(&mut self, mutations: usize) {
        let old_exp_state = self.rng.exp_disabled;
        if self.rng.rand(0, 1) == 0 {
            self.rng.exp_disabled = true;
        }

        for _ in 0..mutations {
            let sel = self.rng.rand(0, Self::STRATEGIES.len() - 1);
            let strat = Self::STRATEGIES[sel];
            strat(self);
        }

        self.rng.exp_disabled = old_exp_state;
    }
}

impl VMInputT<CairoState, CairoAddress, ConciseCairoInput> for CairoInput {
    fn mutate<S>(&mut self, _state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasCaller<CairoAddress> + HasMetadata,
    {
        let mut strategy = Strategy {
            input: self.felts.clone(),
            accessed: Vec::new(),
            max_input_size: 1024,
            rng: Rng {
                seed: 0x12640367f4b7ea35,
                exp_disabled: false,
            },
        };
        strategy.mutate(4);
        self.felts = strategy.input.clone();
        MutationResult::Mutated
    }

    fn get_caller(&self) -> CairoAddress {
        todo!()
    }

    fn set_caller(&mut self, _caller: CairoAddress) {
        todo!()
    }

    fn get_contract(&self) -> CairoAddress {
        todo!()
    }

    fn get_state(&self) -> &CairoState {
        &self.sstate.state
    }

    fn get_caller_mut(&mut self) -> &mut CairoAddress {
        todo!()
    }

    fn get_state_mut(&mut self) -> &mut CairoState {
        todo!()
    }

    fn set_staged_state(
        &mut self,
        state: crate::state_input::StagedVMState<CairoAddress, CairoState, ConciseCairoInput>,
        idx: usize,
    ) {
        self.sstate = state;
        self.sstate_idx = idx;
    }

    fn get_state_idx(&self) -> usize {
        todo!()
    }

    fn get_staged_state(
        &self,
    ) -> &crate::state_input::StagedVMState<CairoAddress, CairoState, ConciseCairoInput> {
        &self.sstate
    }

    fn set_as_post_exec(&mut self, _out_size: usize) {
        todo!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn fav_factor(&self) -> f64 {
        todo!()
    }

    fn get_data_abi(&self) -> Option<crate::evm::abi::BoxedABI> {
        todo!()
    }

    fn get_data_abi_mut(&mut self) -> &mut Option<crate::evm::abi::BoxedABI> {
        todo!()
    }

    fn get_txn_value_temp(&self) -> Option<crate::evm::types::EVMU256> {
        todo!()
    }

    fn get_direct_data(&self) -> Vec<u8> {
        todo!()
    }

    fn get_concise<Out: Default>(
        &self,
        exec_res: &ExecutionResult<CairoAddress, CairoState, Out, ConciseCairoInput>,
    ) -> ConciseCairoInput {
        ConciseCairoInput::from_input(self, exec_res)
    }
}

impl Input for CairoInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }
    fn wrapped_as_testcase(&mut self) {}
}

impl Debug for CairoInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CairoInput")
            .field("felts", &self.felts)
            .field("sstate", &self.sstate)
            .finish()
    }
}
