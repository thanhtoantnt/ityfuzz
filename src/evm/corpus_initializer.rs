use crate::{
    dump_txn,
    evm::{
        abi::{get_abi_type_boxed, BoxedABI},
        bytecode_analyzer,
        contract_utils::{extract_sig_from_contract, ABIConfig, ContractLoader},
        input::{ConciseEVMInput, EVMInput},
        types::{
            fixed_address, EVMAddress, EVMFuzzState, EVMInfantStateState, EVMStagedVMState,
            ProjectSourceMapTy, EVMU256,
        },
        vm::{EVMExecutor, EVMState},
    },
    fuzzer::{DUMP_FILE_COUNT, REPLAY},
    generic_vm::vm_executor::GenericVM,
    input::ConciseSerde,
    mutator::AccessPattern,
    state::HasCaller,
    state_input::StagedVMState,
};
use bytes::Bytes;
use hex;
use libafl::{
    corpus::{Corpus, Testcase},
    impl_serdeany,
    prelude::HasMetadata,
    schedulers::Scheduler,
    state::HasCorpus,
};
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::File,
    io::Write,
    path::Path,
    rc::Rc,
    time::Duration,
};

use crate::evm::types::EVMExecutionResult;

pub struct EVMCorpusInitializer<'a> {
    executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
    scheduler: &'a dyn Scheduler<EVMInput, EVMFuzzState>,
    infant_scheduler: &'a dyn Scheduler<EVMStagedVMState, EVMInfantStateState>,
    state: &'a mut EVMFuzzState,
    work_dir: String,
}

pub struct EVMInitializationArtifacts {
    pub address_to_sourcemap: ProjectSourceMapTy,
    pub address_to_bytecode: HashMap<EVMAddress, Bytecode>,
    pub address_to_abi: HashMap<EVMAddress, Vec<ABIConfig>>,
    pub address_to_abi_object: HashMap<EVMAddress, Vec<BoxedABI>>,
    pub address_to_name: HashMap<EVMAddress, String>,
    pub initial_state: EVMStagedVMState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ABIMap {
    pub signature_to_abi: HashMap<[u8; 4], ABIConfig>,
}

impl_serdeany!(ABIMap);

impl ABIMap {
    pub fn new() -> Self {
        Self {
            signature_to_abi: HashMap::new(),
        }
    }

    pub fn insert(&mut self, abi: ABIConfig) {
        self.signature_to_abi.insert(abi.function.clone(), abi);
    }

    pub fn get(&self, signature: &[u8; 4]) -> Option<&ABIConfig> {
        self.signature_to_abi.get(signature)
    }
}

#[macro_export]
macro_rules! handle_contract_insertion {
    ($state: expr, $host: expr, $deployed_address: expr, $abi: expr) => {
        let (is_erc20, is_pair) = match $host.flashloan_middleware {
            Some(ref middleware) => {
                let mut mid = middleware.deref().borrow_mut();
                mid.on_contract_insertion(&$deployed_address, &$abi, $state)
            }
            None => (false, false),
        };
        if is_erc20 {
            register_borrow_txn(&$host, $state, $deployed_address);
        }
        if is_pair {
            let mut mid = $host
                .flashloan_middleware
                .as_ref()
                .unwrap()
                .deref()
                .borrow_mut();
            mid.on_pair_insertion(&$host, $state, $deployed_address);
        }
    };
}

macro_rules! wrap_input {
    ($input: expr) => {{
        let mut tc = Testcase::new($input);
        tc.set_exec_time(Duration::from_secs(0));
        tc
    }};
}

macro_rules! add_input_to_corpus {
    ($state: expr, $scheduler: expr, $input: expr) => {
        let idx = $state
            .add_tx_to_corpus(wrap_input!($input))
            .expect("failed to add");
        $scheduler
            .on_add($state, idx)
            .expect("failed to call scheduler on_add");
    };
}

impl<'a> EVMCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
        scheduler: &'a dyn Scheduler<EVMInput, EVMFuzzState>,
        infant_scheduler: &'a dyn Scheduler<EVMStagedVMState, EVMInfantStateState>,
        state: &'a mut EVMFuzzState,
        work_dir: String,
    ) -> Self {
        Self {
            executor,
            scheduler,
            infant_scheduler,
            state,
            work_dir,
        }
    }

    pub fn initialize(&mut self, loader: &mut ContractLoader) -> EVMInitializationArtifacts {
        self.state.metadata_mut().insert(ABIMap::new());
        self.setup_default_callers();
        self.setup_contract_callers();
        self.initialize_contract(loader);
        self.initialize_corpus(loader)
    }

    pub fn initialize_contract(&mut self, loader: &mut ContractLoader) {
        for contract in &mut loader.contracts {
            println!("Deploying contract: {}", contract.name);
            let deployed_address = if !contract.is_code_deployed {
                match self.executor.deploy(
                    Bytecode::new_raw(Bytes::from(contract.code.clone())),
                    Some(Bytes::from(contract.constructor_args.clone())),
                    contract.deployed_address,
                    self.state,
                ) {
                    Some(addr) => addr,
                    None => {
                        println!("Failed to deploy contract: {}", contract.name);
                        // we could also panic here
                        continue;
                    }
                }
            } else {
                // directly set bytecode
                let contract_code = Bytecode::new_raw(Bytes::from(contract.code.clone()));
                bytecode_analyzer::add_analysis_result_to_state(&contract_code, self.state);
                self.executor
                    .host
                    .set_code(contract.deployed_address, contract_code, self.state);
                contract.deployed_address
            };

            contract.deployed_address = deployed_address;
            self.state.add_address(&deployed_address);
        }
    }

    pub fn initialize_corpus(&mut self, loader: &mut ContractLoader) -> EVMInitializationArtifacts {
        let mut artifacts = EVMInitializationArtifacts {
            address_to_bytecode: HashMap::new(),
            address_to_sourcemap: HashMap::new(),
            address_to_abi: HashMap::new(),
            address_to_abi_object: Default::default(),
            address_to_name: Default::default(),
            initial_state: StagedVMState::new_uninitialized(),
        };
        for contract in &mut loader.contracts {
            if contract.abi.len() == 0 {
                // this contract's abi is not available, we will use 3 layers to handle this
                // 1. Extract abi from bytecode, and see do we have any function sig available in state
                // 2. Use Heimdall to extract abi
                // 3. Reconfirm on failures of heimdall
                println!("Contract {} has no abi", contract.name);
                let contract_code = hex::encode(contract.code.clone());
                let sigs = extract_sig_from_contract(&contract_code);
                for sig in &sigs {
                    if let Some(abi) = self.state.metadata().get::<ABIMap>().unwrap().get(sig) {
                        contract.abi.push(abi.clone());
                    }
                }
            }

            artifacts
                .address_to_sourcemap
                .insert(contract.deployed_address, contract.source_map.clone());
            artifacts
                .address_to_abi
                .insert(contract.deployed_address, contract.abi.clone());
            let mut code = vec![];
            self.executor
                .host
                .code
                .clone()
                .get(&contract.deployed_address)
                .map(|c| {
                    code.extend_from_slice(c.bytecode());
                });
            artifacts.address_to_bytecode.insert(
                contract.deployed_address,
                Bytecode::new_raw(Bytes::from(code)),
            );

            let mut name = contract.name.clone().trim_end_matches('*').to_string();
            if name != format!("{:?}", contract.deployed_address) {
                name = format!("{}({:?})", name, contract.deployed_address.clone());
            }
            artifacts
                .address_to_name
                .insert(contract.deployed_address, name);

            for abi in contract.abi.clone() {
                self.add_abi(
                    &abi,
                    self.scheduler,
                    contract.deployed_address,
                    &mut artifacts,
                );
            }
            // add transfer txn
            {
                let input = EVMInput {
                    caller: self.state.get_rand_caller(),
                    contract: contract.deployed_address,
                    data: None,
                    sstate: StagedVMState::new_uninitialized(),
                    sstate_idx: 0,
                    txn_value: Some(EVMU256::from(1)),
                    step: false,
                    env: Default::default(),
                    access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                    direct_data: Default::default(),
                    randomness: vec![0],
                    repeat: 1,
                };
                add_input_to_corpus!(self.state, self.scheduler, input);
            }
        }
        artifacts.initial_state =
            StagedVMState::new_with_state(self.executor.host.evmstate.clone());

        let mut tc = Testcase::new(artifacts.initial_state.clone());
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .state
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        self.infant_scheduler
            .on_add(&mut self.state.infant_states_state, idx)
            .expect("failed to call infant scheduler on_add");
        artifacts
    }

    pub fn setup_default_callers(&mut self) {
        let default_callers = HashSet::from([
            fixed_address("8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"),
            fixed_address("35c9dfd76bf02107ff4f7128Bd69716612d31dDb"),
            // fixed_address("5E6B78f0748ACd4Fb4868dF6eCcfE41398aE09cb"),
        ]);

        for caller in default_callers {
            self.state.add_caller(&caller);
        }
    }

    pub fn setup_contract_callers(&mut self) {
        let contract_callers = HashSet::from([
            fixed_address("e1A425f1AC34A8a441566f93c82dD730639c8510"),
            fixed_address("68Dd4F5AC792eAaa5e36f4f4e0474E0625dc9024"),
            // fixed_address("aF97EE5eef1B02E12B650B8127D8E8a6cD722bD2"),
        ]);
        for caller in contract_callers {
            self.state.add_caller(&caller);
            self.executor.host.set_code(
                caller,
                Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])),
                self.state,
            );
        }
    }

    fn add_abi(
        &mut self,
        abi: &ABIConfig,
        scheduler: &dyn Scheduler<EVMInput, EVMFuzzState>,
        deployed_address: EVMAddress,
        artifacts: &mut EVMInitializationArtifacts,
    ) {
        if abi.is_constructor {
            return;
        }

        match self
            .state
            .hash_to_address
            .get_mut(abi.function.clone().as_slice())
        {
            Some(addrs) => {
                addrs.insert(deployed_address);
            }
            None => {
                self.state
                    .hash_to_address
                    .insert(abi.function.clone(), HashSet::from([deployed_address]));
            }
        }
        #[cfg(not(feature = "fuzz_static"))]
        if abi.is_static {
            return;
        }
        let mut abi_instance = get_abi_type_boxed(&abi.abi);
        abi_instance.set_func_with_name(abi.function, abi.function_name.clone());

        artifacts
            .address_to_abi_object
            .entry(deployed_address)
            .or_insert(vec![])
            .push(abi_instance.clone());
        let input = EVMInput {
            caller: self.state.get_rand_caller(),
            contract: deployed_address,
            data: Some(abi_instance),
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: if abi.is_payable {
                Some(EVMU256::ZERO)
            } else {
                None
            },
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            direct_data: Default::default(),
            randomness: vec![0],
            repeat: 1,
        };
        add_input_to_corpus!(self.state, scheduler, input.clone());

        let corpus_dir = format!("{}/corpus", self.work_dir.as_str()).to_string();
        dump_txn!(corpus_dir, &input)
    }
}
