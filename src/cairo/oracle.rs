use std::{collections::hash_map::DefaultHasher, hash::Hasher};

use itertools::Itertools;

use crate::oracle::Oracle;

use super::{
    input::{CairoInput, ConciseCairoInput},
    types::{CairoAddress, CairoFuzzState},
    vm::CairoState,
};

pub struct TypedBugOracle {}

impl TypedBugOracle {
    pub fn new() -> Self {
        Self {}
    }
}

impl
    Oracle<
        CairoState,
        CairoAddress,
        usize,
        usize,
        Vec<u8>,
        CairoInput,
        CairoFuzzState,
        ConciseCairoInput,
    > for TypedBugOracle
{
    fn transition(
        &self,
        _ctx: &mut crate::oracle::OracleCtx<
            CairoState,
            CairoAddress,
            usize,
            usize,
            Vec<u8>,
            CairoInput,
            CairoFuzzState,
            ConciseCairoInput,
        >,
        _stage: u64,
    ) -> u64 {
        todo!()
    }

    fn oracle(
        &self,
        ctx: &mut crate::oracle::OracleCtx<
            CairoState,
            CairoAddress,
            usize,
            usize,
            Vec<u8>,
            CairoInput,
            CairoFuzzState,
            ConciseCairoInput,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        if ctx.post_state.typed_bug.len() > 0 {
            ctx.post_state
                .typed_bug
                .iter()
                .map(|_| {
                    let hasher = DefaultHasher::new();

                    (hasher.finish() as u64) << 8
                })
                .collect_vec()
        } else {
            vec![]
        }
    }
}
