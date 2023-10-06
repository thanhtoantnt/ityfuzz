use libafl::prelude::tuple_list;

pub struct CairoFuzzConfig {
    pub target: String,
    pub work_dir: String,
    pub seed: u64,
}

pub fn cairo_fuzzer(config: &CairoFuzzConfig) {
    let mut state: CairoFuzzState = FuzzState::new(config.seed);
    let mut vm: CairoVM<CairoFunctionInput, CairoFuzzState> = CairoVM::new();
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    let infant_scheduler = CairoVMStateScheduler {
        inner: SortedDroppingScheduler::new(),
    };
    let mut scheduler = CairoTestcaseScheduler {
        inner: QueueScheduler::new(),
    };

    {
        CairoCorpusInitializer::new(&mut state, &mut vm, &scheduler, &infant_scheduler)
            .setup(vec![config.target.clone()]);
    }

    let vm_ref = Rc::new(RefCell::new(vm));

    let jmp_observer = StdMapObserver::new("jmp", vm_ref.borrow().get_jmp());
    let mut feedback: MapFeedback<CairoFunctionInput, _, _, _, CairoFuzzState, _> =
        MaxMapFeedback::new(&jmp_observer);
    feedback
        .init_state(&mut state)
        .expect("Failed to init state");

    let mutator = CairoFuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(std_stage);

    let mut executor = FuzzExecutor::new(vm_ref.clone(), tuple_list!(jmp_observer));

    let infant_feedback =
        CmpFeedback::new(vm_ref.borrow().get_cmp(), &infant_scheduler, vm_ref.clone());
    let infant_result_feedback =
        DataflowFeedback::new(vm_ref.borrow().get_read(), vm_ref.borrow().get_write());

    let mut oracles: Vec<Rc<RefCell<dyn Oracle<_, _, _, _, _, _, _, _, _, _>>>> =
        vec![Rc::new(RefCell::new(TypedBugOracle::new()))];
    let mut producers = vec![];

    let objective = OracleFeedback::new(&mut oracles, &mut producers, vm_ref.clone());

    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        infant_feedback,
        infant_result_feedback,
        objective,
        config.work_dir.clone(),
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Fuzzing failed");
}
