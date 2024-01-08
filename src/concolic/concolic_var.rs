use z3::{Context, ast::BV};

#[derive(Clone, Debug)]
pub struct ConcolicVar<'a> {
    pub concrete: i32,
    pub symbolic: BV<'a>, // to be able to do bitwise operations 
}

impl<'a> ConcolicVar<'a> {
    pub fn new(concrete: i32, symbolic_name: &str, ctx: &'a Context, sz: u32) -> Self {
        let symbolic: BV<'a> = BV::new_const(ctx, symbolic_name, sz);
        ConcolicVar { concrete, symbolic }
    }

    pub fn new_from_bv(concrete: i32, symbolic: BV<'a>) -> Self {
        ConcolicVar { concrete, symbolic }
    }

    pub fn update_concrete(&mut self, new_value: i32) {
        self.concrete = new_value;
    }

    pub fn update_symbolic(&mut self, new_expr: BV<'a>) {
        self.symbolic = new_expr;
    }

    // Arithmetic ADD operation
    pub fn add(&mut self, other: &ConcolicVar<'a>, _ctx: &'a Context) {
        self.concrete += other.concrete;
        self.symbolic = self.symbolic.bvadd(&other.symbolic);
    }

    // Arithmetic SUB operation
    pub fn sub(&mut self, other: &ConcolicVar<'a>, _ctx: &'a Context) {
        self.concrete -= other.concrete;
        self.symbolic = self.symbolic.bvsub(&other.symbolic);
    }

    // Bitwise NOT operation
    pub fn not(&self) -> Self {
        Self {
            concrete: !self.concrete,
            symbolic: self.symbolic.bvnot(),
        }
    }

    // Bitwise AND operation
    pub fn and(&self, other: &Self) -> Self {
        Self {
            concrete: self.concrete & other.concrete,
            symbolic: self.symbolic.bvand(&other.symbolic),
        }
    }

    // Bitwise OR operation
    pub fn or(&self, other: &Self) -> Self {
        Self {
            concrete: self.concrete | other.concrete,
            symbolic: self.symbolic.bvor(&other.symbolic),
        }
    }

    // Bitwise XOR operation
    pub fn xor(&self, other: &Self) -> Self {
        Self {
            concrete: self.concrete ^ other.concrete,
            symbolic: self.symbolic.bvxor(&other.symbolic),
        }
    }

    // Bitwise NAND operation
    pub fn nand(&self, other: &Self) -> Self {
        Self {
            concrete: !(self.concrete & other.concrete),
            symbolic: self.symbolic.bvand(&other.symbolic).bvnot(),
        }
    }

    // Bitwise NOR operation
    pub fn nor(&self, other: &Self) -> Self {
        Self {
            concrete: !(self.concrete | other.concrete),
            symbolic: self.symbolic.bvor(&other.symbolic).bvnot(),
        }
    }

    // Bitwise XNOR operation
    pub fn xnor(&self, other: &Self) -> Self {
        Self {
            concrete: !(self.concrete ^ other.concrete),
            symbolic: self.symbolic.bvxor(&other.symbolic).bvnot(),
        }
    }

    // Bitwise left shift operation
    pub fn shl(&self, other: &Self) -> Self {
        Self {
            concrete: self.concrete << other.concrete,
            symbolic: self.symbolic.bvshl(&other.symbolic),
        }
    }

    // Bitwise logical right shift operation
    pub fn lshr(&self, other: &Self) -> Self {
        Self {
            concrete: ((self.concrete as u64) >> other.concrete) as i32,  // Logical shift for unsigned values
            symbolic: self.symbolic.bvlshr(&other.symbolic),
        }
    }

    // Bitwise arithmetic right shift operation
    pub fn ashr(&self, other: &Self) -> Self {
        Self {
            concrete: self.concrete >> other.concrete,  // Arithmetic shift for signed values
            symbolic: self.symbolic.bvashr(&other.symbolic),
        }
    }
}

