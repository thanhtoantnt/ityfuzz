use std::{cell::RefCell, rc::Rc};

use cairo_rs::types::program::Program;
use libafl::{
    prelude::{
        tuple_list, Feedback, MaxMapFeedback, SimpleEventManager, SimpleMonitor, StdMapObserver,
    },
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    Fuzzer,
};

use crate::{
    cairo::{
        config::CairoFuzzConfig,
        corpus_initializer::CairoCorpusInitializer,
        input::{CairoInput, ConciseCairoInput},
        oracle::TypedBugOracle,
        types::{CairoAddress, CairoFuzzMutator, CairoFuzzState, Function},
        vm::{CairoExecutor, CairoState},
    },
    evm::host::JMP_MAP,
    executor::FuzzExecutor,
    feedback::OracleFeedback,
    fuzzer::ItyFuzzer,
    mutator::FuzzMutator,
    scheduler::SortedDroppingScheduler,
};

use serde_json::Value;

pub fn cairo_fuzzer(
    config: CairoFuzzConfig<
        CairoState,
        CairoAddress,
        usize,
        usize,
        Vec<(u32, u32)>,
        CairoInput,
        CairoFuzzState,
        ConciseCairoInput,
    >,
    state: &mut CairoFuzzState,
) {
    let contents = std::fs::read_to_string(&config.input).expect("Cannot read the file");
    let function = match parse_json(&contents, &config.func_name) {
        Some(func) => func,
        None => {
            eprintln!("Could not parse json file");
            std::process::exit(1)
        }
    };

    let program = Program::from_bytes(&contents.as_bytes(), Some(&function.name))
        .expect("Cannot deserialize Program");
    let jmps = unsafe { &mut JMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp", jmps);

    let mut scheduler = QueueScheduler::new();
    let infant_scheduler = SortedDroppingScheduler::new();

    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    feedback.init_state(state).expect("Failed to init state");

    let mut oracles = config.oracles;
    oracles.push(Rc::new(RefCell::new(TypedBugOracle::new())));

    let mut cairo_executor: CairoExecutor<
        CairoInput,
        CairoFuzzState,
        CairoState,
        ConciseCairoInput,
    > = CairoExecutor::new(program, function);

    let mut corpus_initializer = CairoCorpusInitializer::new(
        &mut cairo_executor,
        &mut scheduler,
        &infant_scheduler,
        state,
        config.work_dir.clone(),
    );

    corpus_initializer.initialize(config.func_name);

    let cairo_executor_ref = Rc::new(RefCell::new(cairo_executor));

    let objective = OracleFeedback::new(&mut oracles, cairo_executor_ref.clone());

    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        objective,
        config.work_dir,
    );

    let mutator: CairoFuzzMutator<'_> = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(std_stage);

    let mut executor = FuzzExecutor::new(cairo_executor_ref.clone(), tuple_list!(jmp_observer));

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
        .expect("Fuzzing failed");
}

/// Function that returns a vector of the args type of the function the user want to fuzz
fn get_type_args(members: &Value) -> Vec<String> {
    let mut type_args = Vec::<String>::new();
    for (_, value) in members
        .as_object()
        .expect("Failed get member type_args as object from json")
    {
        type_args.push(value["cairo_type"].to_string().replace("\"", ""));
    }
    return type_args;
}

/// Function to parse cairo json artifact
pub fn parse_json(data: &String, function_name: &String) -> Option<Function> {
    let data: Value = serde_json::from_str(&data).expect("JSON was not well-formatted");
    let hints = if let Some(field) = data.get("hints") {
        field.as_object().unwrap().len() != 0
    } else {
        false
    };
    if let Some(identifiers) = data.get("identifiers") {
        for (key, value) in identifiers
            .as_object()
            .expect("Failed to get identifier from json")
        {
            let name = key.split(".").last().unwrap().to_string();
            if value["type"] == "function" && &name == function_name {
                let pc = value["pc"].to_string();
                if let Some(identifiers_key) = identifiers.get(format!("{}.Args", key)) {
                    if let (Some(size), Some(members)) =
                        (identifiers_key.get("size"), identifiers_key.get("members"))
                    {
                        return Some(Function {
                            decorators: Vec::new(),
                            entrypoint: pc,
                            hints,
                            name,
                            num_args: size
                                .as_u64()
                                .expect("Failed to get number of arguments from json"),
                            type_args: get_type_args(members),
                        });
                    }
                }
            }
        }
    }
    return None;
}
