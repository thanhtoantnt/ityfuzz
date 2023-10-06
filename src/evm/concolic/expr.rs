use crate::evm::types::EVMU256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum ConcolicOp {
    EVMU256(EVMU256),
    ADD,
    DIV,
    MUL,
    SUB,
    SDIV,
    SMOD,
    UREM,
    SREM,
    AND,
    OR,
    XOR,
    NOT,
    SHL,
    SHR,
    SAR,
    SLICEDINPUT(EVMU256),
    BALANCE,
    CALLVALUE,
    CALLER,
    // symbolic byte
    SYMBYTE(String),
    // helper OP for input slicing (not in EVM)
    CONSTBYTE(u8),
    // (start, end) in bytes, end is not included
    FINEGRAINEDINPUT(u32, u32),
    // constraint OP here
    EQ,
    LT,
    SLT,
    GT,
    SGT,
    LNOT,

    // high / low
    SELECT(u32, u32),
    CONCAT,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Expr {
    pub(crate) lhs: Option<Box<Expr>>,
    pub(crate) rhs: Option<Box<Expr>>,
    // concrete should be used in constant folding
    // concrete: Option<EVMU256>,
    pub(crate) op: ConcolicOp,
}

impl Expr {
    fn pretty_print_helper(&self, paddings: usize) -> String {
        let mut s = String::new();
        let noop = self.lhs.is_none() && self.rhs.is_none();
        if noop {
            s.push_str(format!("{:?}", self.op).as_str());
        } else {
            s.push_str(format!("{:?}(", self.op).as_str());
            s.push_str(
                format!(
                    "{}",
                    match self.lhs {
                        Some(ref lhs) => format!("{},", lhs.pretty_print_helper(paddings + 1)),
                        None => "".to_string(),
                    }
                )
                .as_str(),
            );
            s.push_str(
                format!(
                    "{}",
                    match self.rhs {
                        Some(ref rhs) => rhs.pretty_print_helper(paddings + 1),
                        None => "".to_string(),
                    }
                )
                .as_str(),
            );
            s.push_str(format!(")").as_str());
        }
        s
    }

    pub fn pretty_print(&self) {
        println!("{}", self.pretty_print_helper(0));
    }

    pub fn pretty_print_str(&self) -> String {
        self.pretty_print_helper(0)
    }
}

// pub struct Constraint {
//     pub lhs: Box<Expr>,
//     pub rhs: Box<Expr>,
//     pub op: ConstraintOp,
// }

// TODO: if both operands are concrete we can do constant folding somewhere
#[macro_export]
macro_rules! box_bv {
    ($lhs:expr, $rhs:expr, $op:expr) => {
        Box::new(Expr {
            lhs: Some(Box::new($lhs)),
            rhs: Some($rhs),
            op: $op,
        })
    };
}

#[macro_export]
macro_rules! bv_from_u256 {
    ($val:expr, $ctx:expr) => {{
        let u64x4 = $val.as_limbs();
        let bv = BV::from_u64(&$ctx, u64x4[3], 64);
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[2], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[1], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[0], 64));
        bv
    }};
}

impl Expr {
    pub fn new_sliced_input(idx: EVMU256) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::SLICEDINPUT(idx),
        })
    }

    pub fn new_balance() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::BALANCE,
        })
    }

    pub fn new_callvalue() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::CALLVALUE,
        })
    }

    pub fn new_caller() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::CALLER,
        })
    }

    pub fn sliced_input(start: u32, end: u32) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::FINEGRAINEDINPUT(start, end),
        })
    }

    pub fn concat(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::CONCAT)
    }

    pub fn div(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::DIV)
    }
    pub fn mul(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::MUL)
    }
    pub fn add(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::ADD)
    }
    pub fn sub(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SUB)
    }
    pub fn bvsdiv(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SDIV)
    }
    pub fn bvsmod(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SMOD)
    }
    pub fn bvurem(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::UREM)
    }
    pub fn bvsrem(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SREM)
    }
    pub fn bvand(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::AND)
    }
    pub fn bvor(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::OR)
    }
    pub fn bvxor(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::XOR)
    }
    pub fn bvnot(self) -> Box<Expr> {
        Box::new(Expr {
            lhs: Some(Box::new(self)),
            rhs: None,
            op: ConcolicOp::NOT,
        })
    }
    pub fn bvshl(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SHL)
    }
    pub fn bvlshr(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SHR)
    }
    pub fn bvsar(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SAR)
    }

    pub fn bvult(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::LT)
    }

    pub fn bvugt(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::GT)
    }

    pub fn bvslt(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SLT)
    }

    pub fn bvsgt(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SGT)
    }

    pub fn equal(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::EQ)
    }

    pub fn sym_byte(s: String) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::SYMBYTE(s),
        })
    }

    pub fn const_byte(b: u8) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::CONSTBYTE(b),
        })
    }

    // logical not
    pub fn lnot(self) -> Box<Expr> {
        Box::new(Expr {
            lhs: Some(Box::new(self)),
            rhs: None,
            op: ConcolicOp::LNOT,
        })
    }

    pub fn is_concrete(&self) -> bool {
        match (&self.lhs, &self.rhs) {
            (Some(l), Some(r)) => l.is_concrete() && r.is_concrete(),
            (None, None) => match self.op {
                ConcolicOp::EVMU256(_) => true,
                ConcolicOp::SLICEDINPUT(_) => false,
                ConcolicOp::BALANCE => false,
                ConcolicOp::CALLVALUE => false,
                ConcolicOp::SYMBYTE(_) => false,
                ConcolicOp::CONSTBYTE(_) => true,
                ConcolicOp::FINEGRAINEDINPUT(_, _) => false,
                ConcolicOp::CALLER => false,
                _ => unreachable!(),
            },
            (Some(l), None) => l.is_concrete(),
            _ => unreachable!(),
        }
    }

    pub fn depth(&self) -> u32 {
        if self.lhs.is_none() && self.rhs.is_none() {
            return 0;
        }

        let mut lhs_depth = 0;
        let mut rhs_depth = 0;

        if let Some(ref l) = self.lhs {
            lhs_depth = l.depth();
        }

        if let Some(ref r) = self.rhs {
            rhs_depth = r.depth();
        }

        std::cmp::max(lhs_depth, rhs_depth) + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConcatOptCtx {
    low: u32,
    high: u32,
    on_expr: Option<Box<Expr>>,
}

impl ConcatOptCtx {
    pub fn merge(&mut self, other: ConcatOptCtx) -> bool {
        if other.on_expr != self.on_expr || other.on_expr.is_none() || self.on_expr.is_none() {
            return false;
        }
        if self.low == other.high + 1 {
            self.low = other.low;
            true
        } else if self.high + 1 == other.low {
            self.high = other.high;
            true
        } else {
            false
        }
    }
}

fn simplify_concat_select_helper(expr: Box<Expr>) -> (ConcatOptCtx, Box<Expr>) {
    let lhs_info = expr.lhs.map(|e| simplify_concat_select_helper(e));
    let rhs_info = expr.rhs.map(|e| simplify_concat_select_helper(e));
    let op = expr.op;
    let mut new_expr = Box::new(Expr {
        lhs: lhs_info.clone().map(|(_ctx, e)| e),
        rhs: rhs_info.clone().map(|(_ctx, e)| e),
        op: op.clone(),
    });

    let mut ctx = ConcatOptCtx {
        low: 0,
        high: 0,
        on_expr: None,
    };

    match op {
        ConcolicOp::CONCAT => {
            let (mut lhs_ctx, _) = lhs_info.unwrap();
            let (rhs_ctx, _) = rhs_info.unwrap();
            if lhs_ctx.merge(rhs_ctx.clone()) {
                ctx = lhs_ctx;
                new_expr = Box::new(Expr {
                    lhs: ctx.on_expr.clone(),
                    rhs: None,
                    op: ConcolicOp::SELECT(ctx.high, ctx.low),
                });
            }
        }
        ConcolicOp::SELECT(high, low) => {
            ctx.low = low;
            ctx.high = high;
            assert!(new_expr.lhs.is_some());
            ctx.on_expr = new_expr.lhs.clone();
        }

        _ => {}
    }
    (ctx, new_expr)
}

pub fn simplify_concat_select(expr: Box<Expr>) -> Box<Expr> {
    simplify_concat_select_helper(expr).1
}

pub fn simplify(expr: Box<Expr>) -> Box<Expr> {
    let expr = simplify_concat_select(expr);
    expr
}
