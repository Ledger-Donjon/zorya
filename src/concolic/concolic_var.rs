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




#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context, ast::{BV, Ast}};

    #[test]
    fn test_new_and_new_from_bv() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let symbolic = BV::new_const(&ctx, "x", 32);
        let concolic_var = ConcolicVar::new(10, "x", &ctx, 32);
        let concolic_var_from_bv = ConcolicVar::new_from_bv(10, symbolic.clone());

        assert_eq!(concolic_var.concrete, 10);
        assert_eq!(concolic_var_from_bv.concrete, 10);
        assert!(concolic_var.symbolic._eq(&symbolic).simplify().as_bool().unwrap());
    }

    #[test]
    fn test_update_concrete() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let symbolic = BV::new_const(&ctx, "x", 32);
        let mut concolic_var = ConcolicVar::new_from_bv(10, symbolic);

        concolic_var.update_concrete(20);
        assert_eq!(concolic_var.concrete, 20);
        // Does not affect the symbolic part
    }

    #[test]
    fn test_arithmetic_operations() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let symbolic_x = BV::new_const(&ctx, "x", 32);
        let symbolic_y = BV::new_const(&ctx, "y", 32);
        let mut concolic_var1 = ConcolicVar::new_from_bv(10, symbolic_x.clone());
        let concolic_var2 = ConcolicVar::new_from_bv(5, symbolic_y.clone());

        // Test for addition
        concolic_var1.add(&concolic_var2, &ctx);
        assert_eq!(concolic_var1.concrete, 15);
        assert_eq!(concolic_var1.symbolic.simplify(),
            symbolic_x.bvadd(&symbolic_y).simplify());

        // Reset concolic_var1 for subtraction test
        let mut concolic_var1 = ConcolicVar::new_from_bv(10, symbolic_x.clone());

        // Test for subtraction
        concolic_var1.sub(&concolic_var2, &ctx);
        assert_eq!(concolic_var1.concrete, 10 - 5);
        // subtraction is often represented as addition with a negated operand
        let negated_y = symbolic_y.bvneg(); // Negating y
        assert_eq!(concolic_var1.symbolic.simplify(),
            symbolic_x.bvadd(&negated_y).simplify());
    }

    #[test]
    fn test_bitwise_operations() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let symbolic_x = BV::new_const(&ctx, "x", 32);
        let symbolic_y = BV::new_const(&ctx, "y", 32);
        let concolic_var1 = ConcolicVar::new_from_bv(10, symbolic_x.clone());
        let concolic_var2 = ConcolicVar::new_from_bv(5, symbolic_y.clone());

        let result_not = concolic_var1.not();
        assert_eq!(result_not.concrete, !10);
        assert_eq!(result_not.symbolic.simplify(), symbolic_x.bvnot().simplify());
        assert!(result_not.symbolic._eq(&symbolic_x.bvnot()).simplify().as_bool().expect("Failed to compare symbolic expressions in NOT operation"));

        let result_and = concolic_var1.and(&concolic_var2);
        assert_eq!(result_and.concrete, 10 & 5);
        assert_eq!(result_and.symbolic.simplify(), symbolic_x.bvand(&symbolic_y).simplify());
        assert!(result_and.symbolic._eq(&symbolic_x.bvand(&symbolic_y)).simplify().as_bool().expect("Failed to compare symbolic expressions in AND operation"));
    }

}


