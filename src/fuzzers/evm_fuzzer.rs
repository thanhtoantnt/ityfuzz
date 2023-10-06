use bytes::Bytes;
use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;

use std::sync::Arc;

use crate::{
    evm::contract_utils::FIX_DEPLOYER, evm::host::FuzzHost, evm::vm::EVMExecutor,
    executor::FuzzExecutor, fuzzer::ItyFuzzer,
};
use glob::glob;
use libafl::feedbacks::Feedback;
use libafl::prelude::HasMetadata;
use libafl::prelude::{QueueScheduler, SimpleEventManager};
use libafl::stages::StdMutationalStage;
use libafl::{
    prelude::{tuple_list, MaxMapFeedback, SimpleMonitor, StdMapObserver},
    Evaluator, Fuzzer,
};

use crate::evm::host::CALL_UNTIL;
use crate::evm::host::{
    ACTIVE_MATCH_EXT_CALL, CMP_MAP, JMP_MAP, PANIC_ON_BUG, READ_MAP, WRITE_MAP, WRITE_RELATIONSHIPS,
};
use crate::evm::vm::EVMState;
use crate::feedback::{CmpFeedback, DataflowFeedback, OracleFeedback};

use crate::scheduler::SortedDroppingScheduler;
use crate::state::HasExecutionResult;

use crate::evm::config::Config;
use crate::evm::corpus_initializer::EVMCorpusInitializer;
use crate::evm::input::{ConciseEVMInput, EVMInput};

use crate::evm::mutator::FuzzMutator;
use crate::evm::onchain::onchain::{OnChain, WHITELIST_ADDR};

use crate::evm::types::{fixed_address, EVMAddress, EVMFuzzMutator, EVMFuzzState, EVMU256};

use revm_primitives::Bytecode;

use crate::evm::abi::ABIAddressToInstanceMap;
use crate::evm::blaz::builder::ArtifactInfoMetadata;

use crate::evm::concolic::concolic_stage::{ConcolicFeedbackWrapper, ConcolicStage};
use crate::evm::cov_stage::CoverageStage;
use crate::evm::feedbacks::Sha3WrappedFeedback;
use crate::evm::middlewares::call_printer::CallPrinter;
use crate::evm::middlewares::coverage::{Coverage, EVAL_COVERAGE};
use crate::evm::middlewares::middleware::Middleware;
use crate::evm::middlewares::sha3_bypass::{Sha3Bypass, Sha3TaintAnalysis};
use crate::evm::oracles::typed_bug::TypedBugOracle;
use crate::evm::srcmap::parser::BASE_PATH;
use crate::fuzzer::{REPLAY, RUN_FOREVER};
use crate::input::ConciseSerde;
use crate::oracle::BugMetadata;

pub fn evm_fuzzer(
    config: Config<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
    >,
    state: &mut EVMFuzzState,
) {
    // create work dir if not exists
    let path = Path::new(config.work_dir.as_str());
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();
    let mut scheduler = QueueScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let cmps = unsafe { &mut CMP_MAP };
    let reads = unsafe { &mut READ_MAP };
    let writes = unsafe { &mut WRITE_MAP };
    let jmp_observer = StdMapObserver::new("jmp", jmps);

    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(Arc::new(scheduler.clone()), config.work_dir.clone());
    fuzz_host.set_spec_id(config.spec_id);

    let _onchain_middleware = match config.onchain.clone() {
        Some(onchain) => {
            Some({
                let mid = Rc::new(RefCell::new(
                    OnChain::<EVMState, EVMInput, EVMFuzzState>::new(
                        // scheduler can be cloned because it never uses &mut self
                        onchain,
                        config.onchain_storage_fetching.unwrap(),
                    ),
                ));

                if let Some(builder) = config.builder {
                    mid.borrow_mut().add_builder(builder);
                }

                fuzz_host.add_middlewares(mid.clone());
                mid
            })
        }
        None => {
            // enable active match for offchain fuzzing (todo: handle this more elegantly)
            unsafe {
                ACTIVE_MATCH_EXT_CALL = true;
            }
            None
        }
    };

    if config.write_relationship {
        unsafe {
            WRITE_RELATIONSHIPS = true;
        }
    }

    unsafe {
        BASE_PATH = config.base_path;
    }

    if config.run_forever {
        unsafe {
            RUN_FOREVER = true;
        }
    }

    unsafe {
        PANIC_ON_BUG = config.panic_on_bug;
    }

    if config.only_fuzz.len() > 0 {
        unsafe {
            WHITELIST_ADDR = Some(config.only_fuzz);
        }
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

    // now evm executor is ready, we can clone it

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
    // let calibration = CalibrationStage::new(&feedback);
    let concolic_stage = ConcolicStage::new(
        config.concolic,
        config.concolic_caller,
        evm_executor_ref.clone(),
    );
    let mutator: EVMFuzzMutator<'_> = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);

    let call_printer_mid = Rc::new(RefCell::new(CallPrinter::new(
        artifacts.address_to_name.clone(),
        artifacts.address_to_sourcemap.clone(),
    )));

    let coverage_obs_stage = CoverageStage::new(
        evm_executor_ref.clone(),
        cov_middleware.clone(),
        call_printer_mid.clone(),
        config.work_dir.clone(),
    );

    let mut stages = tuple_list!(std_stage, concolic_stage, coverage_obs_stage);

    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_caller(&deployer);
    let infant_feedback = CmpFeedback::new(cmps, &infant_scheduler, evm_executor_ref.clone());
    let infant_result_feedback = DataflowFeedback::new(reads, writes);

    let mut oracles = config.oracle;

    if config.typed_bug {
        oracles.push(Rc::new(RefCell::new(TypedBugOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    state.add_metadata(BugMetadata::new());

    let mut producers = config.producers;

    let objective = OracleFeedback::new(&mut oracles, &mut producers, evm_executor_ref.clone());
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
        infant_feedback,
        infant_result_feedback,
        objective,
        config.work_dir,
    );
    match config.replay_file {
        None => {
            fuzzer
                .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
                .expect("Fuzzing failed");
        }
        Some(files) => {
            unsafe {
                EVAL_COVERAGE = true;
            }

            let printer = Rc::new(RefCell::new(CallPrinter::new(
                artifacts.address_to_name.clone(),
                artifacts.address_to_sourcemap.clone(),
            )));
            evm_executor_ref
                .borrow_mut()
                .host
                .add_middlewares(printer.clone());

            let initial_vm_state = artifacts.initial_state.clone();
            for file in glob(files.as_str()).expect("Failed to read glob pattern") {
                let mut f = File::open(file.expect("glob issue")).expect("Failed to open file");
                let mut transactions = String::new();
                f.read_to_string(&mut transactions)
                    .expect("Failed to read file");

                let mut vm_state = initial_vm_state.clone();

                let mut idx = 0;

                for txn in transactions.split("\n") {
                    idx += 1;
                    // let splitter = txn.split(" ").collect::<Vec<&str>>();
                    if txn.len() < 4 {
                        continue;
                    }

                    // [is_step] [caller] [target] [input] [value]
                    let (inp, call_until) = ConciseEVMInput::deserialize_concise(txn.as_bytes())
                        .to_input(vm_state.clone());
                    printer.borrow_mut().cleanup();

                    unsafe {
                        CALL_UNTIL = call_until;
                    }

                    fuzzer
                        .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                        .unwrap();

                    println!("============ Execution result {} =============", idx);
                    println!(
                        "reverted: {:?}",
                        state.get_execution_result().clone().reverted
                    );
                    println!("call trace:\n{}", printer.deref().borrow().get_trace());
                    println!(
                        "output: {:?}",
                        hex::encode(state.get_execution_result().clone().output)
                    );

                    // println!(
                    //     "new_state: {:?}",
                    //     state.get_execution_result().clone().new_state.state
                    // );
                    println!("================================================");

                    vm_state = state.get_execution_result().new_state.clone();
                }
            }

            // dump coverage:
            cov_middleware.borrow_mut().record_instruction_coverage();
        }
    }
}
