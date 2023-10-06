use crate::evm::types::{fixed_address, generate_random_address, EVMAddress, EVMFuzzState};
use glob::glob;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;

use itertools::Itertools;
use std::io::Read;
use std::path::Path;

extern crate crypto;

use crate::evm::abi::get_abi_type_boxed_with_address;
use crate::evm::srcmap::parser::{decode_instructions, SourceMapLocation};

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;

use crate::evm::bytecode_iterator::all_bytecode;
use revm_interpreter::opcode::PUSH4;
use serde::{Deserialize, Serialize};

// to use this address, call rand_utils::fixed_address(FIX_DEPLOYER)
pub static FIX_DEPLOYER: &str = "8b21e662154b4bbc1ec0754d0238875fe3d22fa6";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIConfig {
    pub abi: String,
    pub function: [u8; 4],
    pub function_name: String,
    pub is_static: bool,
    pub is_payable: bool,
    pub is_constructor: bool,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub name: String,
    pub code: Vec<u8>,
    pub abi: Vec<ABIConfig>,
    pub is_code_deployed: bool,
    pub constructor_args: Vec<u8>,
    pub deployed_address: EVMAddress,
    pub source_map: Option<HashMap<usize, SourceMapLocation>>,
}

#[derive(Debug, Clone)]
pub struct ABIInfo {
    pub source: String,
    pub abi: Vec<ABIConfig>,
}

#[derive(Debug, Clone)]
pub struct ContractLoader {
    pub contracts: Vec<ContractInfo>,
    pub abis: Vec<ABIInfo>,
}

pub fn set_hash(name: &str, out: &mut [u8]) {
    let mut hasher = Sha3::keccak256();
    hasher.input_str(name);
    hasher.result(out)
}

impl ContractLoader {
    fn parse_abi(path: &Path) -> Vec<ABIConfig> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data)
            .expect("failed to read abis file");
        return Self::parse_abi_str(&data);
    }

    fn process_input(ty: String, input: &Value) -> String {
        if let Some(slot) = input.get("components") {
            if ty == "tuple" {
                let v = slot
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Self::process_input(v["type"].as_str().unwrap().to_string(), v))
                    .collect::<Vec<String>>()
                    .join(",");
                return format!("({})", v);
            } else if ty.ends_with("[]") {
                return format!(
                    "{}[]",
                    Self::process_input(ty[..ty.len() - 2].to_string(), input)
                );
            }
            panic!("unknown type: {}", ty);
        } else {
            ty
        }
    }

    pub fn parse_abi_str(data: &String) -> Vec<ABIConfig> {
        let json: Vec<Value> = serde_json::from_str(&data).expect("failed to parse abis file");
        json.iter()
            .flat_map(|abi| {
                if abi["type"] == "function" || abi["type"] == "constructor" {
                    let name = if abi["type"] == "function" {
                        abi["name"].as_str().expect("failed to parse abis name")
                    } else {
                        "constructor"
                    };
                    let mut abi_name: Vec<String> = vec![];
                    abi["inputs"]
                        .as_array()
                        .expect("failed to parse abis inputs")
                        .iter()
                        .for_each(|input| {
                            abi_name.push(Self::process_input(
                                input["type"].as_str().unwrap().to_string(),
                                input,
                            ));
                        });
                    let mut abi_config = ABIConfig {
                        abi: format!("({})", abi_name.join(",")),
                        function: [0; 4],
                        function_name: name.to_string(),
                        is_static: abi["stateMutability"].as_str().unwrap_or_default() == "view",
                        is_payable: abi["stateMutability"].as_str().unwrap_or_default()
                            == "payable",
                        is_constructor: abi["type"] == "constructor",
                    };
                    let function_to_hash = format!("{}({})", name, abi_name.join(","));
                    // print name and abi_name
                    println!("{}({})", name, abi_name.join(","));

                    set_hash(function_to_hash.as_str(), &mut abi_config.function);
                    Some(abi_config)
                } else {
                    None
                }
            })
            .collect()
    }

    fn parse_hex_file(path: &Path) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        hex::decode(data).expect("Failed to parse hex file")
    }

    fn constructor_args_encode(constructor_args: &Vec<String>) -> Vec<u8> {
        constructor_args
            .iter()
            .flat_map(|arg| {
                let arg = if arg.starts_with("0x") {
                    &arg[2..]
                } else {
                    arg
                };
                let arg = if arg.len() % 2 == 1 {
                    format!("0{}", arg)
                } else {
                    arg.to_string()
                };
                let mut decoded = hex::decode(arg).unwrap();
                let len = decoded.len();
                if len < 32 {
                    let mut padding = vec![0; 32 - len]; // Create a vector of zeros
                    padding.append(&mut decoded); // Append the original vector to it
                    padding
                } else {
                    decoded
                }
            })
            .collect()
    }

    pub fn from_prefix(
        prefix: &str,
        state: &mut EVMFuzzState,
        source_map_info: Option<ContractsSourceMapInfo>,
        proxy_deploy_codes: &Vec<String>,
        constructor_args: &Vec<String>,
    ) -> Self {
        let contract_name = prefix.split("/").last().unwrap().replace("*", "");

        // get constructor args
        let constructor_args_in_bytes: Vec<u8> = Self::constructor_args_encode(constructor_args);

        // create dummy contract info
        let mut contract_result = ContractInfo {
            name: prefix.to_string(),
            code: vec![],
            abi: vec![],
            is_code_deployed: false,
            constructor_args: constructor_args_in_bytes,
            deployed_address: generate_random_address(state),
            source_map: source_map_info.map(|info| {
                info.get(contract_name.as_str())
                    .expect(
                        format!(
                            "combined.json provided but contract ({:?}) not found",
                            contract_name
                        )
                        .as_str(),
                    )
                    .clone()
            }),
        };
        let mut abi_result = ABIInfo {
            source: prefix.to_string(),
            abi: vec![],
        };

        println!("Loading contract {}", prefix);

        // Load contract, ABI, and address from file
        for i in glob(prefix).expect("not such path for prefix") {
            match i {
                Ok(path) => {
                    if path.to_str().unwrap().ends_with(".abi") {
                        // this is an ABI file
                        abi_result.abi = Self::parse_abi(&path);
                        contract_result.abi = abi_result.abi.clone();
                        // println!("ABI: {:?}", result.abis);
                    } else if path.to_str().unwrap().ends_with(".bin") {
                        // this is an BIN file
                        contract_result.code = Self::parse_hex_file(&path);
                    } else if path.to_str().unwrap().ends_with(".address") {
                        // this is deployed address
                        contract_result
                            .deployed_address
                            .0
                            .clone_from_slice(Self::parse_hex_file(&path).as_slice());
                    } else {
                        println!("Found unknown file: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }

        if let Some(abi) = abi_result.abi.iter().find(|abi| abi.is_constructor) {
            let mut abi_instance =
                get_abi_type_boxed_with_address(&abi.abi, fixed_address(FIX_DEPLOYER).0.to_vec());
            abi_instance.set_func_with_name(abi.function, abi.function_name.clone());
            if contract_result.constructor_args.len() == 0 {
                println!("No constructor args found, using default constructor args");
                contract_result.constructor_args = abi_instance.get().get_bytes();
            }
            // println!("Constructor args: {:?}", result.constructor_args);
            contract_result
                .code
                .extend(contract_result.constructor_args.clone());
        } else {
            println!("No constructor in ABI found, skipping");
        }

        // now check if contract is deployed through proxy by checking function signatures
        // if it is, then we use the new bytecode from proxy
        // todo: find a better way to do this
        let current_code = hex::encode(&contract_result.code);
        for deployed_code in proxy_deploy_codes {
            // if deploy_code startwiths '0x' then remove it
            let deployed_code_cleaned = if deployed_code.starts_with("0x") {
                &deployed_code[2..]
            } else {
                deployed_code
            };

            // match all function signatures, compare sigs between our code and deployed code from proxy
            let deployed_code_sig: Vec<[u8; 4]> = extract_sig_from_contract(deployed_code_cleaned);
            let current_code_sig: Vec<[u8; 4]> = extract_sig_from_contract(&current_code);

            // compare deployed_code_sig and current_code_sig
            if deployed_code_sig.len() == current_code_sig.len() {
                let mut is_match = true;
                for i in 0..deployed_code_sig.len() {
                    if deployed_code_sig[i] != current_code_sig[i] {
                        is_match = false;
                        break;
                    }
                }
                if is_match {
                    contract_result.code =
                        hex::decode(deployed_code_cleaned).expect("Failed to parse deploy code");
                }
            }
        }
        return Self {
            contracts: if contract_result.code.len() > 0 {
                vec![contract_result]
            } else {
                vec![]
            },
            abis: vec![abi_result],
        };
    }

    // This function loads constructs Contract infos from path p
    // The organization of directory p should be
    // p
    // |- contract1.abi
    // |- contract1.bin
    // |- contract2.abi
    // |- contract2.bin
    pub fn from_glob(
        p: &str,
        state: &mut EVMFuzzState,
        proxy_deploy_codes: &Vec<String>,
        constructor_args_map: &HashMap<String, Vec<String>>,
    ) -> Self {
        let mut prefix_file_count: HashMap<String, u8> = HashMap::new();
        let mut contract_combined_json_info = None;
        for i in glob(p).expect("not such folder") {
            match i {
                Ok(path) => {
                    let path_str = path.to_str().unwrap();
                    if path_str.ends_with(".abi") {
                        *prefix_file_count
                            .entry(path_str.replace(".abi", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with(".bin") {
                        *prefix_file_count
                            .entry(path_str.replace(".bin", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with("combined.json") {
                        contract_combined_json_info = Some(path_str.to_string());
                    } else {
                        println!("Found unknown file in folder: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }

        let parsed_contract_info = match contract_combined_json_info {
            None => None,
            Some(file_name) => {
                let mut combined_json = File::open(file_name).unwrap();
                let mut buf = String::new();
                combined_json.read_to_string(&mut buf).unwrap();
                Some(parse_combined_json(buf))
            }
        };

        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];
        for (prefix, count) in prefix_file_count
            .iter()
            .sorted_by_key(|(k, _)| <&String>::clone(k))
        {
            let p = prefix.to_string();
            if *count > 0 {
                let mut constructor_args: Vec<String> = vec![];
                for (k, v) in constructor_args_map.iter() {
                    let components: Vec<&str> = p.split('/').collect();
                    if let Some(last_component) = components.last() {
                        if last_component == k {
                            constructor_args = v.clone();
                        }
                    }
                }
                let prefix_loader = Self::from_prefix(
                    (prefix.to_owned() + &String::from('*')).as_str(),
                    state,
                    parsed_contract_info.clone(),
                    proxy_deploy_codes,
                    &constructor_args,
                );
                prefix_loader
                    .contracts
                    .iter()
                    .for_each(|c| contracts.push(c.clone()));
                prefix_loader.abis.iter().for_each(|a| abis.push(a.clone()));
            }
        }

        ContractLoader { contracts, abis }
    }
}

type ContractsSourceMapInfo = HashMap<String, HashMap<usize, SourceMapLocation>>;

pub fn parse_combined_json(json: String) -> ContractsSourceMapInfo {
    let map_json = serde_json::from_str::<serde_json::Value>(&json).unwrap();

    let contracts = map_json["contracts"]
        .as_object()
        .expect("contracts not found");
    let file_list = map_json["sourceList"]
        .as_array()
        .expect("sourceList not found")
        .iter()
        .map(|x| x.as_str().expect("sourceList is not string").to_string())
        .collect::<Vec<String>>();

    let mut result = ContractsSourceMapInfo::new();

    for (contract_name, contract_info) in contracts {
        let splitter = contract_name.split(':').collect::<Vec<&str>>();
        let _file_name = splitter.iter().take(splitter.len() - 1).join(":");
        let contract_name = splitter.last().unwrap().to_string();

        let bin_runtime = contract_info["bin-runtime"]
            .as_str()
            .expect("bin-runtime not found");
        let bin_runtime_bytes = hex::decode(bin_runtime).expect("bin-runtime is not hex");

        let srcmap_runtime = contract_info["srcmap-runtime"]
            .as_str()
            .expect("srcmap-runtime not found");

        result.insert(
            contract_name.clone(),
            decode_instructions(bin_runtime_bytes, srcmap_runtime.to_string(), &file_list),
        );
    }
    result
}

pub fn extract_sig_from_contract(code: &str) -> Vec<[u8; 4]> {
    let bytes = hex::decode(code).expect("failed to decode contract code");
    let mut code_sig = HashSet::new();

    let bytecode = all_bytecode(&bytes);

    for (pc, op) in bytecode {
        if op == PUSH4 {
            // ensure we have enough bytes
            if pc + 6 >= bytes.len() {
                break;
            }

            // Solidity: check whether next ops is EQ
            // Vyper: check whether next 2 ops contain XOR
            if bytes[pc + 5] == 0x14
                || bytes[pc + 5] == 0x18
                || bytes[pc + 6] == 0x18
                || bytes[pc + 6] == 0x14
            {
                let mut sig_bytes = vec![];
                for j in 0..4 {
                    sig_bytes.push(*bytes.get(pc + j + 1).unwrap());
                }
                code_sig.insert(sig_bytes.try_into().unwrap());
            }
        }
    }
    code_sig.iter().cloned().collect_vec()
}
