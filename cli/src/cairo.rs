use clap::Parser;

use ityfuzz::cairo::config::CairoFuzzConfig;
use ityfuzz::cairo::input::CairoInput;
use ityfuzz::cairo::input::ConciseCairoInput;
use ityfuzz::cairo::types::CairoAddress;
use ityfuzz::cairo::types::CairoFuzzState;
use ityfuzz::cairo::vm::CairoState;
use ityfuzz::fuzzers::cairo_fuzzer::cairo_fuzzer;
use ityfuzz::oracle::Oracle;
use ityfuzz::state::FuzzState;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CairoArgs {
    /// Input JSON file
    #[arg(short, long)]
    input_file: String,

    /// Input function name
    #[arg(short, long)]
    function: String,

    /// random seed
    #[arg(long, default_value = "1667840158231589000")]
    seed: u64,
}

pub fn cairo_main(args: CairoArgs) {
    println!("Start fuzzing Cairo input file: {}", args.input_file);

    let oracles: Vec<
        Rc<
            RefCell<
                dyn Oracle<
                    CairoState,
                    CairoAddress,
                    _,
                    _,
                    Vec<(u32, u32)>,
                    CairoInput,
                    CairoFuzzState,
                    ConciseCairoInput,
                >,
            >,
        >,
    > = vec![];

    let config: CairoFuzzConfig<
        CairoState,
        usize,
        usize,
        usize,
        Vec<(u32, u32)>,
        CairoInput,
        FuzzState<CairoInput, CairoState, usize, Vec<(u32, u32)>, ConciseCairoInput>,
        ConciseCairoInput,
    > = CairoFuzzConfig {
        oracles,
        input: args.input_file,
        func_name: args.function,
        work_dir: "work_dir".to_string(),
    };

    let mut state: CairoFuzzState = FuzzState::new(args.seed);

    cairo_fuzzer(config, &mut state)
}
