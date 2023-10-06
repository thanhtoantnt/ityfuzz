use std::collections::hash_map::DefaultHasher;

use crate::evm::contract_utils::ABIConfig;
use heimdall::decompile::decompile_with_bytecode;
use heimdall::decompile::out::solidity::ABIStructure;

use std::hash::Hash;

pub fn fetch_abi_heimdall(bytecode: String) -> Vec<ABIConfig> {
    let mut hasher = DefaultHasher::new();
    bytecode.hash(&mut hasher);
    let heimdall_result = decompile_with_bytecode(bytecode, "".to_string());
    let mut result = vec![];
    for heimdall_abi in heimdall_result {
        match heimdall_abi {
            ABIStructure::Function(func) => {
                let mut inputs = vec![];
                for input in func.inputs {
                    let ty = input.type_;
                    if ty == "bytes" {
                        inputs.push("unknown".to_string());
                    } else {
                        inputs.push(ty);
                    }
                }

                let name = func.name.replace("Unresolved_", "");
                let mut abi_config = ABIConfig {
                    abi: format!("({})", inputs.join(",")),
                    function: [0; 4],
                    function_name: name.clone(),
                    is_static: func.state_mutability == "view",
                    is_payable: func.state_mutability == "payable",
                    is_constructor: false,
                };
                abi_config
                    .function
                    .copy_from_slice(hex::decode(name).unwrap().as_slice());
                result.push(abi_config)
            }
            _ => {
                continue;
            }
        }
    }
    result
}
