use std::{cell::RefCell, rc::Rc};

use crate::oracle::Oracle;

pub struct Config<VS, Addr, Code, By, Out, I, S, CI> {
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Out, I, S, CI>>>>,
    pub input: String,
}
