use z3::{Context, ast::BV};

#[derive(Clone, Debug, PartialEq)]
pub struct ConcolicVar<'a> {
    pub concrete: u32,
    pub symbolic: BV<'a>, // BitVector for bitwise operations 
}

impl<'a> ConcolicVar<'a> {
    pub fn new(concrete: u32, symbolic_name: &str, ctx: &'a Context, sz: u32) -> Self {
        let symbolic: BV<'a> = BV::new_const(ctx, symbolic_name, sz);
        ConcolicVar { concrete, symbolic }
    }

    pub fn new_from_bv(concrete: u32, symbolic: BV<'a>) -> Self {
        ConcolicVar { concrete, symbolic }
    }

    pub fn update_concrete(&mut self, new_value: u32) {
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
    pub fn not(&mut self) {
        self.concrete = !self.concrete;
        self.symbolic = self.symbolic.bvnot();
    }

    // Bitwise AND operation
    pub fn and(&mut self, other: &Self) {
        self.concrete &= other.concrete;
        self.symbolic = self.symbolic.bvand(&other.symbolic);
    }

    // Bitwise OR operation
    pub fn or(&self, other: &Self) {
        let _ = self.concrete | other.concrete;
        self.symbolic.bvor(&other.symbolic);
    }

    // Bitwise XOR operation
    pub fn xor(&self, other: &Self) {
        let _ = self.concrete ^ other.concrete;
        self.symbolic.bvxor(&other.symbolic);
    }

    // Bitwise NAND operation
    pub fn nand(&mut self, other: &Self) {
        self.concrete = !(self.concrete & other.concrete);
        self.symbolic = self.symbolic.bvand(&other.symbolic).bvnot();
    }

    // Bitwise NOR operation
    pub fn nor(&mut self, other: &Self) {
        self.concrete = !(self.concrete | other.concrete);
        self.symbolic = self.symbolic.bvor(&other.symbolic).bvnot();
    }

    // Bitwise XNOR operation
    pub fn xnor(&mut self, other: &Self) {
        self.concrete = !(self.concrete ^ other.concrete);
        self.symbolic = self.symbolic.bvxor(&other.symbolic).bvnot();
    }

    // Bitwise left shift operation
    pub fn shl(&mut self, other: &Self) {
        self.concrete = self.concrete << other.concrete;
        self.symbolic = self.symbolic.bvshl(&other.symbolic);
    }

    // Bitwise logical right shift operation
    pub fn lshr(&mut self, other: &Self) {
        self.concrete = ((self.concrete as u64) >> other.concrete) as u32;  // Logical shift for unsigned values
        self.symbolic = self.symbolic.bvlshr(&other.symbolic);
    }

    // Bitwise arithmetic right shift operation
    pub fn ashr(&mut self, other: &Self) {
        self.concrete = self.concrete >> other.concrete;  // Arithmetic shift for signed values
        self.symbolic = self.symbolic.bvashr(&other.symbolic);
    }

    // Bitwise equality operation
    pub fn equals(&self, other: &Self) -> bool {
        self.concrete == other.concrete && self.symbolic.eq(&other.symbolic)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context, ast::{BV, Ast}};

    #[test]
    fn test_concolic_var_creation() {
        let config = Config::new();
        let context = Context::new(&config);
        
        let var_name = "test_var";
        let concrete_value = 42;
        let size = 32;
        let concolic_var = ConcolicVar::new(concrete_value, var_name, &context, size);

        assert_eq!(concolic_var.concrete, concrete_value);
        assert_eq!(concolic_var.symbolic.get_size(), size as u32);
        assert!(concolic_var.symbolic.is_const());
    }

    #[test]
    fn test_concolic_var_operations() {
        let config = Config::new();
        let context = Context::new(&config);

        let var1 = ConcolicVar::new(10, "var1", &context, 32);
        let var2 = ConcolicVar::new(5, "var2", &context, 32);

        let mut var_add = var1.clone();
        var_add.add(&var2, &context);
        assert_eq!(var_add.concrete, 15);

        let mut var_sub = var1.clone();
        var_sub.sub(&var2, &context);
        assert_eq!(var_sub.concrete, 5);
        // Test for symbolic expression
    }

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
        let mut concolic_var1 = ConcolicVar::new_from_bv(10, symbolic_x.clone());
        let concolic_var2 = ConcolicVar::new_from_bv(5, symbolic_y.clone());

        concolic_var1.not();
        assert_eq!(concolic_var1.concrete, !10);
        assert_eq!(concolic_var1.symbolic.simplify(), symbolic_x.bvnot().simplify());
        assert!(concolic_var1.symbolic._eq(&symbolic_x.bvnot()).simplify().as_bool().expect("Failed to compare symbolic expressions in NOT operation"));

        let mut concolic_var1 = ConcolicVar::new_from_bv(10, symbolic_x.clone());
        concolic_var1.and(&concolic_var2);
        assert_eq!(concolic_var1.concrete, 10 & 5);
        assert_eq!(concolic_var1.symbolic.simplify(), symbolic_x.bvand(&symbolic_y).simplify());
        assert!(concolic_var1.symbolic._eq(&symbolic_x.bvand(&symbolic_y)).simplify().as_bool().expect("Failed to compare symbolic expressions in AND operation"));
    }
}


