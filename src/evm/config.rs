use crate::evm::contract_utils::ContractLoader;
use crate::oracle::Oracle;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use crate::evm::types::EVMAddress;

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
}

pub enum StorageFetchingMode {
    Dump,
    All,
    OneByOne,
}

impl StorageFetchingMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dump" => Some(StorageFetchingMode::Dump),
            "all" => Some(StorageFetchingMode::All),
            "onebyone" => Some(StorageFetchingMode::OneByOne),
            _ => None,
        }
    }
}

impl FuzzerTypes {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "cmp" => Ok(FuzzerTypes::CMP),
            "dataflow" => Ok(FuzzerTypes::DATAFLOW),
            "basic" => Ok(FuzzerTypes::BASIC),
            _ => Err(format!("Unknown fuzzer type: {}", s)),
        }
    }
}

pub struct Config<VS, Addr, Code, By, Out, I, S, CI> {
    pub concolic: bool,
    pub concolic_caller: bool,
    pub fuzzer_type: FuzzerTypes,
    pub contract_loader: ContractLoader,
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Out, I, S, CI>>>>,
    pub state_comp_oracle: Option<String>,
    pub state_comp_matching: Option<String>,
    pub work_dir: String,
    pub write_relationship: bool,
    pub run_forever: bool,
    pub sha3_bypass: bool,
    pub base_path: String,
    pub echidna_oracle: bool,
    pub panic_on_bug: bool,
    pub spec_id: String,
    pub only_fuzz: HashSet<EVMAddress>,
    pub typed_bug: bool,
    pub selfdestruct_bug: bool,
    pub arbitrary_external_call: bool,
}
