use revm_interpreter::opcode::{INVALID, JUMP, JUMPI, RETURN, REVERT, STOP};

pub static mut SKIP_CBOR: bool = false;

pub fn all_bytecode(bytes: &Vec<u8>) -> Vec<(usize, u8)> {
    if bytes.len() == 0 {
        return vec![];
    }
    let mut i = 0;
    let last_op = *bytes.last().unwrap();
    let has_cbor = last_op != JUMP
        && last_op != JUMPI
        && last_op != STOP
        && last_op != INVALID
        && last_op != REVERT
        && last_op != RETURN;

    let cbor_len = if has_cbor && !unsafe { SKIP_CBOR } {
        // load last 2 bytes as big endian
        let len = bytes.len();
        let last_2 = *bytes.get(len - 2).unwrap() as usize;
        let last_1 = *bytes.get(len - 1).unwrap() as usize;
        (last_2 << 8) + last_1 + 2
    } else {
        0
    };

    let mut res = Vec::new();

    while i < bytes.len() - cbor_len {
        let op = *bytes.get(i).unwrap();
        res.push((i, op));
        i += 1;
        if op >= 0x60 && op <= 0x7f {
            i += op as usize - 0x5f;
        }
    }
    res
}

#[macro_export]
macro_rules! skip_cbor {
    ($e: expr) => {{
        #[cfg(not(test))]
        unsafe {
            SKIP_CBOR = true;
        }
        let res = $e;
        #[cfg(not(test))]
        unsafe {
            SKIP_CBOR = false;
        }
        res
    }};
}
