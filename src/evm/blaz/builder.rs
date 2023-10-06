use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;

use bytes::Bytes;
use itertools::Itertools;
use libafl::impl_serdeany;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::rc::Rc;
use std::str::FromStr;

use crate::evm::input::{ConciseEVMInput, EVMInput};

use crate::evm::srcmap::parser::{decode_instructions_with_replacement, SourceMapLocation};
use crate::evm::types::{EVMAddress, EVMFuzzState, ProjectSourceMapTy};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;

#[derive(Clone)]
pub struct BuildJob {
    pub build_server: String,
    pub replacements: HashMap<EVMAddress, Option<BuildJobResult>>,
}

pub static mut BUILD_SERVER: &str = "https://solc-builder.fuzz.land/";

impl BuildJob {
    pub fn new(
        build_server: String,
        replacements: HashMap<EVMAddress, Option<BuildJobResult>>,
    ) -> Self {
        Self {
            build_server,
            replacements,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJobResult {
    /// (file name, source code)
    pub sources: Vec<(String, String)>,
    pub source_maps: String,
    pub bytecodes: Bytes,
    pub abi: String,
    pub source_maps_replacements: Vec<(String, String)>,

    _cache_src_map: HashMap<usize, SourceMapLocation>,
    _cached: bool,
}

impl BuildJobResult {
    pub fn new(
        sources: Vec<(String, String)>,
        source_maps: String,
        bytecodes: Bytes,
        abi: String,
        replacements: Vec<(String, String)>,
    ) -> Self {
        Self {
            sources,
            source_maps,
            bytecodes,
            abi,
            source_maps_replacements: replacements,
            _cache_src_map: Default::default(),
            _cached: false,
        }
    }

    pub fn from_json(json: &Value) -> Option<Self> {
        let sourcemap = json["sourcemap"].as_str().expect("get sourcemap failed");
        let mut sourcemap_replacements = vec![];
        if let Some(_replaces) = json["replaces"].as_array() {
            sourcemap_replacements = _replaces
                .iter()
                .map(|v| {
                    let v = v.as_array().expect("get replace failed");
                    let source = v[0].as_str().expect("get source failed");
                    let target = v[1].as_str().expect("get target failed");
                    (source.to_string(), target.to_string())
                })
                .collect_vec();
        }
        let bytecode = json["runtime_bytecode"]
            .as_str()
            .expect("get bytecode failed");
        let source_objs = json["sources"].as_object().expect("get sources failed");
        let mut sources = vec![(String::new(), String::new()); source_objs.len()];
        for (k, v) in source_objs {
            let idx = v["id"].as_u64().expect("get source id failed") as usize;
            let code = v["source"].as_str().expect("get source code failed");
            sources[idx] = (k.clone(), code.to_string());
        }

        let abi = serde_json::to_string(&json["abi"]).expect("get abi failed");

        Some(Self {
            sources,
            source_maps: sourcemap.to_string(),
            bytecodes: Bytes::from(hex::decode(bytecode).expect("decode bytecode failed")),
            abi: abi.to_string(),
            source_maps_replacements: sourcemap_replacements,
            _cache_src_map: Default::default(),
            _cached: false,
        })
    }

    pub fn from_multi_file(file_path: String) -> HashMap<EVMAddress, Option<Self>> {
        let content = fs::read_to_string(file_path).expect("read file failed");
        let json = serde_json::from_str::<Value>(&content).expect("parse json failed");
        let json_arr = json.as_object().expect("get json array failed");
        let mut results = HashMap::new();
        for (k, v) in json_arr {
            let result = Self::from_json(v);
            let addr = EVMAddress::from_str(k).expect("parse address failed");
            results.insert(addr, result);
        }
        results
    }

    pub fn get_sourcemap(&mut self, bytecode: Vec<u8>) -> HashMap<usize, SourceMapLocation> {
        if self._cached {
            return self._cache_src_map.clone();
        } else {
            let result = decode_instructions_with_replacement(
                bytecode,
                &self.source_maps_replacements,
                self.source_maps.clone(),
                &self
                    .sources
                    .iter()
                    .map(|(name, _)| (name))
                    .cloned()
                    .collect(),
            );
            self._cache_src_map = result.clone();
            self._cached = true;
            return result;
        }
    }

    pub fn get_sourcemap_executor<VS, Addr, Code, By, SlotTy, Out, I, S: 'static, CI>(
        _self: Option<&mut Self>,
        executor: &mut Rc<RefCell<dyn GenericVM<VS, Code, By, Addr, SlotTy, Out, I, S, CI>>>,
        addr: &EVMAddress,
        additional_sourcemap: &ProjectSourceMapTy,
        pc: usize,
    ) -> Option<SourceMapLocation> {
        if let Some(_self) = _self {
            if _self._cached {
                return _self._cache_src_map.get(&pc).cloned();
            }

            let bytecode = Vec::from(
                (**executor)
                    .borrow_mut()
                    .as_any()
                    .downcast_ref::<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>(
                    )
                    .unwrap()
                    .host
                    .code
                    .get(addr)
                    .unwrap()
                    .clone()
                    .bytecode(),
            );
            return _self.get_sourcemap(bytecode).get(&pc).cloned();
        }

        if let Some(Some(srcmap)) = additional_sourcemap.get(addr) {
            return srcmap.get(&pc).cloned();
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfoMetadata {
    pub info: HashMap<EVMAddress, BuildJobResult>,
}

impl ArtifactInfoMetadata {
    pub fn new() -> Self {
        Self {
            info: HashMap::new(),
        }
    }

    pub fn add(&mut self, addr: EVMAddress, result: BuildJobResult) {
        self.info.insert(addr, result);
    }

    pub fn get(&self, addr: &EVMAddress) -> Option<&BuildJobResult> {
        self.info.get(addr)
    }

    pub fn get_mut(&mut self, addr: &EVMAddress) -> Option<&mut BuildJobResult> {
        self.info.get_mut(addr)
    }
}

impl_serdeany!(ArtifactInfoMetadata);
