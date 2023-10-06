use clap::Parser;
use ityfuzz::evm::config::{Config, FuzzerTypes};
use ityfuzz::evm::contract_utils::ContractLoader;
use ityfuzz::evm::input::{ConciseEVMInput, EVMInput};
use ityfuzz::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
use ityfuzz::evm::vm::EVMState;
use ityfuzz::fuzzers::evm_fuzzer::evm_fuzzer;
use ityfuzz::oracle::Oracle;
use ityfuzz::state::FuzzState;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::str::FromStr;

/// CLI for ItyFuzz for EVM smart contracts
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct EvmArgs {
    /// Glob pattern / address to find contracts
    #[arg(short, long)]
    target: String,

    #[arg(long, default_value = "false")]
    fetch_tx_data: bool,

    #[arg(long, default_value = "http://localhost:5001/data")]
    proxy_address: String,

    #[arg(long, default_value = "")]
    constructor_args: String,

    /// Target type (glob, address) (Default: Automatically infer from target)
    #[arg(long)]
    target_type: Option<String>,

    /// Fuzzer type
    #[arg(long, default_value = "cmp")]
    fuzzer_type: String,

    /// Enable onchain
    #[arg(short, long, default_value = "false")]
    onchain: bool,

    /// Onchain - Chain type (ETH, BSC, POLYGON, MUMBAI)
    #[arg(short, long)]
    chain_type: Option<String>,

    /// Onchain - Block number (Default: 0 / latest)
    #[arg(long)]
    onchain_block_number: Option<u64>,

    /// Onchain Customize - Endpoint URL (Default: inferred from chain-type)
    #[arg(long)]
    onchain_url: Option<String>,

    /// Onchain Customize - Chain ID (Default: inferred from chain-type)
    #[arg(long)]
    onchain_chain_id: Option<u32>,

    /// Onchain Customize - Block explorer URL (Default: inferred from chain-type)
    #[arg(long)]
    onchain_explorer_url: Option<String>,

    /// Onchain Customize - Chain name (used as Moralis handle of chain) (Default: inferred from chain-type)
    #[arg(long)]
    onchain_chain_name: Option<String>,

    /// Onchain Etherscan API Key (Default: None)
    #[arg(long)]
    onchain_etherscan_api_key: Option<String>,

    /// Onchain Local Proxy Address (Default: None)
    #[arg(long)]
    onchain_local_proxy_addr: Option<String>,

    /// Enable Concolic (Experimental)
    #[arg(long, default_value = "false")]
    concolic: bool,

    /// Support Treating Caller as Symbolically  (Experimental)
    #[arg(long, default_value = "false")]
    concolic_caller: bool,

    /// Enable flashloan
    #[arg(short, long, default_value = "false")]
    flashloan: bool,

    /// Flashloan price oracle (onchain/dummy) (Default: DummyPriceOracle)
    #[arg(long, default_value = "dummy")]
    flashloan_price_oracle: String,

    /// Enable ierc20 oracle
    #[arg(short, long, default_value = "false")]
    ierc20_oracle: bool,

    /// Enable pair oracle
    #[arg(short, long, default_value = "false")]
    pair_oracle: bool,

    #[arg(long, default_value = "false")]
    panic_on_bug: bool,

    #[arg(long, default_value = "true")]
    selfdestruct_oracle: bool,

    #[arg(long, default_value = "true")]
    arbitrary_external_call_oracle: bool,

    #[arg(long, default_value = "true")]
    echidna_oracle: bool,

    ///Enable oracle for detecting whether bug() / typed_bug() is called
    #[arg(long, default_value = "true")]
    typed_bug_oracle: bool,

    /// Setting any string here will enable state comparison oracle.
    /// This arg holds file path pointing to state comparison oracle's desired state
    #[arg(long, default_value = "")]
    state_comp_oracle: String,

    /// Matching style for state comparison oracle (Select from "Exact", "DesiredContain", "StateContain")
    #[arg(long, default_value = "Exact")]
    state_comp_matching: String,

    /// Replay?
    #[arg(long)]
    replay_file: Option<String>,

    /// Path of work dir, saves corpus, logs, and other stuffs
    #[arg(long, default_value = "work_dir")]
    work_dir: String,

    /// Write contract relationship to files
    #[arg(long, default_value = "false")]
    write_relationship: bool,

    /// Do not quit when a bug is found, continue find new bugs
    #[arg(long, default_value = "false")]
    run_forever: bool,

    /// random seed
    #[arg(long, default_value = "1667840158231589000")]
    seed: u64,

    /// Whether bypass all SHA3 comparisons, this may break original logic of contracts  (Experimental)
    #[arg(long, default_value = "false")]
    sha3_bypass: bool,

    /// Only fuzz contracts with the addresses, separated by comma
    #[arg(long, default_value = "")]
    only_fuzz: String,

    /// Only needed when using combined.json (source map info).
    /// This is the base path when running solc compile (--base-path passed to solc).
    /// Also, please convert it to absolute path if you are not sure.
    #[arg(long, default_value = "")]
    base_path: String,

    /// Spec ID
    #[arg(long, default_value = "Latest")]
    spec_id: String,

    /// Replacement config (replacing bytecode) for onchain campaign
    #[arg(long, default_value = "")]
    onchain_replacements_file: String,

    /// Offchain Config Url. If specified, will deploy based on offchain config file.
    #[arg(long, default_value = "")]
    offchain_config_url: String,

    /// Offchain Config File. If specified, will deploy based on offchain config file.
    #[arg(long, default_value = "")]
    offchain_config_file: String,
}

enum EVMTargetType {
    Glob,
    Address,
}

pub fn evm_main(args: EvmArgs) {
    let target_type: EVMTargetType = match args.target_type {
        Some(v) => match v.as_str() {
            "glob" => EVMTargetType::Glob,
            "address" => EVMTargetType::Address,
            _ => {
                panic!("Invalid target type")
            }
        },
        None => {
            if args.target.starts_with("0x") {
                EVMTargetType::Address
            } else {
                EVMTargetType::Glob
            }
        }
    };

    let oracles: Vec<
        Rc<
            RefCell<
                dyn Oracle<
                    EVMState,
                    EVMAddress,
                    _,
                    _,
                    EVMU256,
                    Vec<u8>,
                    EVMInput,
                    EVMFuzzState,
                    ConciseEVMInput,
                >,
            >,
        >,
    > = vec![];

    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let proxy_deploy_codes: Vec<String> = vec![];

    let constructor_args_map = HashMap::new();

    let config = Config {
        fuzzer_type: FuzzerTypes::from_str(args.fuzzer_type.as_str()).expect("unknown fuzzer"),
        contract_loader: match target_type {
            EVMTargetType::Glob => ContractLoader::from_glob(
                args.target.as_str(),
                &mut state,
                &proxy_deploy_codes,
                &constructor_args_map,
            ),
            _ => panic!("Not supported"),
        },
        only_fuzz: if args.only_fuzz.len() > 0 {
            args.only_fuzz
                .split(",")
                .map(|s| EVMAddress::from_str(s).expect("failed to parse only fuzz"))
                .collect()
        } else {
            HashSet::new()
        },
        concolic: args.concolic,
        concolic_caller: args.concolic_caller,
        oracle: oracles,
        state_comp_matching: if args.state_comp_oracle.len() > 0 {
            Some(args.state_comp_matching)
        } else {
            None
        },
        state_comp_oracle: if args.state_comp_oracle.len() > 0 {
            Some(args.state_comp_oracle)
        } else {
            None
        },
        work_dir: args.work_dir,
        write_relationship: args.write_relationship,
        run_forever: args.run_forever,
        sha3_bypass: args.sha3_bypass,
        base_path: args.base_path,
        echidna_oracle: args.echidna_oracle,
        panic_on_bug: args.panic_on_bug,
        spec_id: args.spec_id,
        typed_bug: args.typed_bug_oracle,
        selfdestruct_bug: args.selfdestruct_oracle,
        arbitrary_external_call: args.arbitrary_external_call_oracle,
    };

    match config.fuzzer_type {
        FuzzerTypes::CMP => evm_fuzzer(config, &mut state),
        _ => {}
    }
}
