use std::{cell::RefCell, rc::Rc};

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
        types::{CairoAddress, CairoFuzzMutator, CairoFuzzState},
        vm::{CairoExecutor, CairoState},
    },
    evm::host::JMP_MAP,
    executor::FuzzExecutor,
    feedback::OracleFeedback,
    fuzzer::ItyFuzzer,
    mutator::FuzzMutator,
    scheduler::SortedDroppingScheduler,
};

pub fn cairo_fuzzer(
    config: CairoFuzzConfig<
        CairoState,
        CairoAddress,
        usize,
        usize,
        Vec<u8>,
        CairoInput,
        CairoFuzzState,
        ConciseCairoInput,
    >,
    state: &mut CairoFuzzState,
) {
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
    > = CairoExecutor::new();

    let mut corpus_initializer = CairoCorpusInitializer::new(
        &mut cairo_executor,
        &mut scheduler,
        &infant_scheduler,
        state,
        config.work_dir.clone(),
    );

    corpus_initializer.initialize();

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
