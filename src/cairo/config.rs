use std::{cell::RefCell, rc::Rc};

use crate::oracle::Oracle;

pub struct CairoConfig<VS, Addr, I, S> {
    pub oracles: Vec<Rc<RefCell<dyn Oracle<VS, Addr, I, S>>>>,
    pub input: String,
}
