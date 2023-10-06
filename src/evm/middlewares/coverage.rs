use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::srcmap::parser::{
    pretty_print_source_map, SourceMapAvailability, SourceMapWithCode,
};
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm_interpreter::opcode::{INVALID, JUMPDEST, JUMPI, STOP};
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use serde::Serialize;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::evm::bytecode_iterator::all_bytecode;
use crate::evm::types::{is_zero, EVMAddress, ProjectSourceMapTy};
use crate::evm::vm::IN_DEPLOY;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use serde_json;

pub static mut EVAL_COVERAGE: bool = false;

/// Finds all PCs (offsets of bytecode) that are instructions / JUMPDEST
/// Returns a tuple of (instruction PCs, JUMPI PCs, Skip PCs)
pub fn instructions_pc(bytecode: &Bytecode) -> (HashSet<usize>, HashSet<usize>, HashSet<usize>) {
    let mut complete_bytes = vec![];
    let mut skip_instructions = HashSet::new();
    let mut total_jumpi_set = HashSet::new();
    all_bytecode(&bytecode.bytes().to_vec())
        .iter()
        .for_each(|(pc, op)| {
            if *op == JUMPDEST || *op == STOP || *op == INVALID {
                skip_instructions.insert(*pc);
            }
            if *op == JUMPI {
                total_jumpi_set.insert(*pc);
            }
            complete_bytes.push(*pc);
        });
    (
        complete_bytes.into_iter().collect(),
        total_jumpi_set,
        skip_instructions,
    )
}

#[derive(Clone, Debug)]
pub struct Coverage {
    pub pc_coverage: HashMap<EVMAddress, HashSet<usize>>,
    pub total_instr_set: HashMap<EVMAddress, HashSet<usize>>,
    pub total_jumpi_set: HashMap<EVMAddress, HashSet<usize>>,
    pub jumpi_coverage: HashMap<EVMAddress, HashSet<(usize, bool)>>,
    pub skip_pcs: HashMap<EVMAddress, HashSet<usize>>,
    pub work_dir: String,

    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
    pub pc_info: HashMap<(EVMAddress, usize), SourceMapWithCode>,

    pub sources: HashMap<EVMAddress, Vec<(String, String)>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageResult {
    pub instruction_coverage: usize,
    pub total_instructions: usize,
    pub branch_coverage: usize,
    pub total_branches: usize,
    pub uncovered: HashSet<SourceMapWithCode>,
    pub uncovered_pc: Vec<usize>,
    pub address: EVMAddress,
}

impl CoverageResult {
    pub fn new() -> Self {
        Self {
            instruction_coverage: 0,
            total_instructions: 0,
            branch_coverage: 0,
            total_branches: 0,
            uncovered: HashSet::new(),
            uncovered_pc: vec![],
            address: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub coverage: HashMap<String, CoverageResult>,
    #[serde(skip)]
    pub files: HashMap<String, Vec<(String, String)>>,
}

impl CoverageReport {
    pub fn new() -> Self {
        Self {
            coverage: HashMap::new(),
            files: Default::default(),
        }
    }

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        for (addr, cov) in &self.coverage {
            s.push_str(&format!("Contract: {}\n", addr));
            s.push_str(&format!(
                "Instruction Coverage: {}/{} ({:.2}%) \n",
                cov.instruction_coverage,
                cov.total_instructions,
                (cov.instruction_coverage * 100) as f64 / cov.total_instructions as f64
            ));
            s.push_str(&format!(
                "Branch Coverage: {}/{} ({:.2}%) \n",
                cov.branch_coverage,
                cov.total_branches,
                (cov.branch_coverage * 100) as f64 / cov.total_branches as f64
            ));

            if cov.uncovered.len() > 0 {
                s.push_str(&format!("Uncovered Code:\n"));
                for uncovered in &cov.uncovered {
                    s.push_str(&format!("{}\n\n", uncovered.to_string()));
                }
            }

            s.push_str(&format!("Uncovered PCs: {:?}\n", cov.uncovered_pc));
            s.push_str(&format!("--------------------------------\n"));
        }
        s
    }

    pub fn dump_file(&self, work_dir: String) {
        let mut text_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!(
                "{}/cov_{}.txt",
                work_dir.clone(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros()
            ))
            .unwrap();
        text_file.write_all(self.to_string().as_bytes()).unwrap();
        text_file.flush().unwrap();

        let mut json_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!(
                "{}/cov_{}.json",
                work_dir,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros()
            ))
            .unwrap();
        json_file
            .write_all(serde_json::to_string(self).unwrap().as_bytes())
            .unwrap();
        json_file.flush().unwrap();

        let mut file_json_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!("{}/../files.json", work_dir))
            .unwrap();
        file_json_file
            .write_all(serde_json::to_string(&self.files).unwrap().as_bytes())
            .unwrap();
        file_json_file.flush().unwrap();
    }

    pub fn summarize(&self) {
        println!("============= Coverage Summary =============");
        for (addr, cov) in &self.coverage {
            println!(
                "{}: {:.2}% Instruction Covered, {:.2}% Branch Covered",
                addr,
                (cov.instruction_coverage * 100) as f64 / cov.total_instructions as f64,
                (cov.branch_coverage * 100) as f64 / cov.total_branches as f64
            );
        }
    }
}

impl Coverage {
    pub fn new(
        sourcemap: ProjectSourceMapTy,
        address_to_name: HashMap<EVMAddress, String>,
        work_dir: String,
    ) -> Self {
        let work_dir = format!("{}/coverage", work_dir);
        if !Path::new(&work_dir).exists() {
            fs::create_dir_all(&work_dir).unwrap();
        }

        Self {
            pc_coverage: HashMap::new(),
            total_instr_set: HashMap::new(),
            total_jumpi_set: Default::default(),
            jumpi_coverage: Default::default(),
            skip_pcs: Default::default(),
            work_dir,
            sourcemap,
            address_to_name,
            pc_info: Default::default(),
            sources: Default::default(),
        }
    }

    pub fn record_instruction_coverage(&mut self) {
        let mut report = CoverageReport::new();

        let default_skipper = HashSet::new();

        for (addr, all_pcs) in &self.total_instr_set {
            let name = self
                .address_to_name
                .get(addr)
                .unwrap_or(&format!("{:?}", addr))
                .clone();
            report.files.insert(
                name.clone(),
                self.sources.get(addr).unwrap_or(&vec![]).clone(),
            );
            match self.pc_coverage.get_mut(addr) {
                None => {}
                Some(covered) => {
                    let skip_pcs = self.skip_pcs.get(addr).unwrap_or(&default_skipper);
                    // Handle Instruction Coverage
                    let real_covered: HashSet<usize> =
                        covered.difference(skip_pcs).cloned().collect();
                    let uncovered_pc = all_pcs.difference(&real_covered).cloned().collect_vec();
                    report.coverage.insert(
                        name.clone(),
                        CoverageResult {
                            instruction_coverage: real_covered.len(),
                            total_instructions: all_pcs.len(),
                            branch_coverage: 0,
                            total_branches: 0,
                            uncovered: HashSet::new(),
                            uncovered_pc: uncovered_pc.clone(),
                            address: addr.clone(),
                        },
                    );

                    let mut result_ref = report.coverage.get_mut(&name).unwrap();
                    for pc in uncovered_pc {
                        if let Some(source_map) = self.pc_info.get(&(*addr, pc)).map(|x| x.clone())
                        {
                            result_ref.uncovered.insert(source_map.clone());
                        }
                    }

                    // Handle Branch Coverage
                    let all_branch_pcs = self.total_jumpi_set.get(addr).unwrap_or(&default_skipper);
                    let empty_set = HashSet::new();
                    let existing_branch_pcs = self
                        .jumpi_coverage
                        .get(addr)
                        .unwrap_or(&empty_set)
                        .iter()
                        .filter(|(pc, _)| !skip_pcs.contains(pc))
                        .collect_vec();
                    result_ref.branch_coverage = existing_branch_pcs.len();
                    result_ref.total_branches = all_branch_pcs.len() * 2;
                }
            }
        }

        // cleanup, remove small contracts
        report.coverage.retain(|_, v| v.total_instructions > 10);
        report.dump_file(self.work_dir.clone());
        report.summarize();
    }
}

impl<I, VS, S> Middleware<VS, I, S> for Coverage
where
    I: Input + VMInputT<VS, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        _host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
        if IN_DEPLOY || !EVAL_COVERAGE {
            return;
        }
        let address = interp.contract.code_address;
        let pc = interp.program_counter();
        self.pc_coverage.entry(address).or_default().insert(pc);

        if *interp.instruction_pointer == JUMPI {
            let condition = is_zero(interp.stack.peek(1).unwrap());
            self.jumpi_coverage
                .entry(address)
                .or_default()
                .insert((pc, condition));
        }
    }

    unsafe fn on_insert(
        &mut self,
        bytecode: &mut Bytecode,
        address: EVMAddress,
        _host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
        let (pcs, jumpis, mut skip_pcs) = instructions_pc(&bytecode.clone());

        pcs.iter().for_each(|pc| {
            match pretty_print_source_map(*pc, &address, &self.sourcemap) {
                SourceMapAvailability::Available(s) => {
                    self.pc_info.insert((address, *pc), s);
                }
                SourceMapAvailability::Unknown => {
                    skip_pcs.insert(*pc);
                }
                SourceMapAvailability::Unavailable => {}
            };
        });

        // total instr minus skipped pcs
        let total_instr = pcs
            .iter()
            .filter(|pc| !skip_pcs.contains(*pc))
            .cloned()
            .collect();
        self.total_instr_set.insert(address, total_instr);

        // total jumpi minus skipped pcs
        let jumpis = jumpis
            .iter()
            .filter(|pc| !skip_pcs.contains(*pc))
            .cloned()
            .collect();
        self.total_jumpi_set.insert(address, jumpis);

        self.skip_pcs.insert(address, skip_pcs);
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::InstructionCoverage
    }
}
