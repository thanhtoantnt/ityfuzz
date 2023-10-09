use std::{cell::RefCell, rc::Rc};

use crate::oracle::Oracle;

pub struct CairoFuzzConfig<VS, Addr, Code, By, Out, I, S, CI> {
    pub oracles: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Out, I, S, CI>>>>,
    pub input: String,
    pub work_dir: String,
}
