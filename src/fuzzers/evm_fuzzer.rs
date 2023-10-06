use crate::{
    evm::{
        abi::ABIAddressToInstanceMap,
        blaz::builder::ArtifactInfoMetadata,
        concolic::concolic_stage::ConcolicFeedbackWrapper,
        config::Config,
        contract_utils::FIX_DEPLOYER,
        corpus_initializer::EVMCorpusInitializer,
        feedbacks::Sha3WrappedFeedback,
        host::{FuzzHost, ACTIVE_MATCH_EXT_CALL, JMP_MAP, WRITE_RELATIONSHIPS},
        input::{ConciseEVMInput, EVMInput},
        middlewares::{
            coverage::Coverage,
            middleware::Middleware,
            sha3_bypass::{Sha3Bypass, Sha3TaintAnalysis},
        },
        mutator::FuzzMutator,
        oracles::typed_bug::TypedBugOracle,
        srcmap::parser::BASE_PATH,
        types::{fixed_address, EVMAddress, EVMFuzzMutator, EVMFuzzState, EVMU256},
        vm::{EVMExecutor, EVMState},
    },
    executor::FuzzExecutor,
    feedback::OracleFeedback,
    fuzzer::{ItyFuzzer, REPLAY},
    oracle::BugMetadata,
    scheduler::SortedDroppingScheduler,
};
use bytes::Bytes;
use libafl::{
    feedbacks::Feedback,
    prelude::{
        tuple_list, HasMetadata, MaxMapFeedback, QueueScheduler, SimpleEventManager, SimpleMonitor,
        StdMapObserver,
    },
    stages::StdMutationalStage,
    Fuzzer,
};
use revm_primitives::Bytecode;
use std::{cell::RefCell, ops::Deref, path::Path, rc::Rc, sync::Arc};

pub fn evm_fuzzer(
    config: Config<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
    >,
    state: &mut EVMFuzzState,
) {
    let path = Path::new(config.work_dir.as_str());
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();
    let mut scheduler = QueueScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp", jmps);

    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(Arc::new(scheduler.clone()), config.work_dir.clone());
    fuzz_host.set_spec_id(config.spec_id);

    if config.write_relationship {
        unsafe {
            WRITE_RELATIONSHIPS = true;
        }
    }

    unsafe {
        ACTIVE_MATCH_EXT_CALL = true;
        BASE_PATH = config.base_path;
    }

    let sha3_taint = Rc::new(RefCell::new(Sha3TaintAnalysis::new()));

    if config.sha3_bypass {
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Sha3Bypass::new(sha3_taint.clone()))));
    }

    let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput> =
        EVMExecutor::new(fuzz_host, deployer);

    if config.replay_file.is_some() {
        // add coverage middleware for replay
        unsafe {
            REPLAY = true;
        }
    }

    let mut corpus_initializer = EVMCorpusInitializer::new(
        &mut evm_executor,
        &mut scheduler,
        &infant_scheduler,
        state,
        config.work_dir.clone(),
    );

    let mut artifacts = corpus_initializer.initialize(&mut config.contract_loader.clone());

    let mut instance_map = ABIAddressToInstanceMap::new();
    artifacts
        .address_to_abi_object
        .iter()
        .for_each(|(addr, abi)| {
            instance_map.map.insert(addr.clone(), abi.clone());
        });

    let cov_middleware = Rc::new(RefCell::new(Coverage::new(
        artifacts.address_to_sourcemap.clone(),
        artifacts.address_to_name.clone(),
        config.work_dir.clone(),
    )));

    evm_executor.host.add_middlewares(cov_middleware.clone());

    state.add_metadata(instance_map);

    evm_executor.host.initialize(state);

    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));
    if !state.metadata().contains::<ArtifactInfoMetadata>() {
        state.metadata_mut().insert(ArtifactInfoMetadata::new());
    }

    let meta = state
        .metadata_mut()
        .get_mut::<ArtifactInfoMetadata>()
        .unwrap();

    for (addr, build_artifact) in &artifacts.build_artifacts {
        meta.add(*addr, build_artifact.clone());
    }

    for (addr, bytecode) in &mut artifacts.address_to_bytecode {
        unsafe {
            cov_middleware.deref().borrow_mut().on_insert(
                bytecode,
                *addr,
                &mut evm_executor_ref.deref().borrow_mut().host,
                state,
            );
        }
    }

    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    feedback.init_state(state).expect("Failed to init state");

    let mutator: EVMFuzzMutator<'_> = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);

    let mut stages = tuple_list!(std_stage);
    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    // let infant_feedback = CmpFeedback::new(cmps, &infant_scheduler, evm_executor_ref.clone());

    let mut oracles = config.oracle;

    if config.typed_bug {
        oracles.push(Rc::new(RefCell::new(TypedBugOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    state.add_metadata(BugMetadata::new());

    let objective = OracleFeedback::new(&mut oracles, evm_executor_ref.clone());
    let wrapped_feedback = ConcolicFeedbackWrapper::new(Sha3WrappedFeedback::new(
        feedback,
        sha3_taint,
        evm_executor_ref.clone(),
        config.sha3_bypass,
    ));

    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        wrapped_feedback,
        objective,
        config.work_dir,
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
        .expect("Fuzzing failed");
}
