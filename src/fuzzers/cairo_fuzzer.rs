// use libafl::prelude::tuple_list;

use crate::{
    cairo::{
        config::CairoFuzzConfig,
        input::{CairoInput, ConciseCairoInput},
        types::{CairoAddress, CairoFuzzState},
        vm::CairoState,
    },
};

pub fn cairo_fuzzer(
    _config: &CairoFuzzConfig<
        CairoState,
        CairoAddress,
        usize,
        usize,
        Vec<u8>,
        CairoInput,
        CairoFuzzState,
        ConciseCairoInput,
    >,
    _state: &mut CairoFuzzState,
) {
    //
}
