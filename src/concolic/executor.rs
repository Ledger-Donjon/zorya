use crate::state::State;
use parser::parser::{Inst, Opcode};
use z3::{Context, Solver, ast::BV};
use crate::concolic::ConcolicVar;

#[derive(Debug)]
pub struct ConcolicExecutor<'a> {
    pub context: &'a Context,
    pub solver: Solver<'a>,
    pub state: State<'a>,
}

impl<'a> ConcolicExecutor<'a> {
    pub fn new(context: &'a Context) -> Self {
        let solver = z3::Solver::new(context);
        let state = State::new(context); 

        ConcolicExecutor { context, solver, state }
    }

    pub fn run(&mut self, instructions: Vec<Inst>) {
        for instruction in instructions {
            println!("Executing instruction: {:?}", instruction);
            self.execute_instruction(&instruction);
        }
    }

    pub fn execute_instruction(&mut self, instruction: &Inst) {
        match instruction.opcode {
            Opcode::Load => self.handle_load(instruction),
            Opcode::IntCarry => self.handle_int_carry(instruction),
            Opcode::IntSCarry => todo!(),
            Opcode::Copy => todo!(),
            Opcode::IntAdd => todo!(),
            Opcode::BoolOr => todo!(),
            Opcode::IntSub => todo!(),
            Opcode::FloatEqual => todo!(),
            Opcode::Store => todo!(),
            Opcode::FloatNotEqual => todo!(),
            Opcode::Branch => todo!(),
            Opcode::FloatLess => todo!(),
            Opcode::CBranch => todo!(),
            Opcode::IntSBorrow => todo!(),
            Opcode::FloatLessEqual => todo!(),
            Opcode::BrandInd => todo!(),
            Opcode::Int2Comp => todo!(),
            Opcode::FloatAdd => todo!(),
            Opcode::Call => todo!(),
            Opcode::IntNegate => todo!(),
            Opcode::FloatSub => todo!(),
            Opcode::CallInd => todo!(),
            Opcode::IntXor => todo!(),
            Opcode::FloatMult => todo!(),
            Opcode::UserDefined => todo!(),
            Opcode::IntAnd => todo!(),
            Opcode::FloatDIV => todo!(),
            Opcode::Return => todo!(),
            Opcode::IntOr => todo!(),
            Opcode::FloatNeg => todo!(),
            Opcode::Piece => todo!(),
            Opcode::IntLeft => todo!(),
            Opcode::FloatAbs => todo!(),
            Opcode::Subpiece => todo!(),
            Opcode::IntRight => todo!(),
            Opcode::FloatSqrt => todo!(),
            Opcode::IntEqual => todo!(),
            Opcode::IntSright => todo!(),
            Opcode::FloatCell => todo!(),
            Opcode::IntNotEqual => todo!(),
            Opcode::IntMult => todo!(),
            Opcode::FloatFloor => todo!(),
            Opcode::IntLess => todo!(),
            Opcode::IntDiv => todo!(),
            Opcode::FloatRound => todo!(),
            Opcode::IntSLess => todo!(),
            Opcode::IntRem => todo!(),
            Opcode::FloatNaN => todo!(),
            Opcode::IntLessEqual => todo!(),
            Opcode::IntSdiv => todo!(),
            Opcode::Int2Float => todo!(),
            Opcode::IntSLessEqual => todo!(),
            Opcode::IntSRem => todo!(),
            Opcode::Float2Float => todo!(),
            Opcode::IntZExt => todo!(),
            Opcode::BoolNegate => todo!(),
            Opcode::Trunc => todo!(),
            Opcode::IntSExt => todo!(),
            Opcode::BoolXor => todo!(),
            Opcode::CPoolRef => todo!(),
            Opcode::BoolAnd => todo!(),
            Opcode::New => todo!(),
            Opcode::CallOther => todo!(),
            // ... other opcodes
        }.expect("REASON");
    }

    fn handle_load(&mut self, instruction: &Inst) -> Result<(), String> {
        match (&instruction.output, instruction.inputs.get(0)) {
            (Some(output), Some(input)) => {
                let source_size = input.size.to_bitvector_size();
                let source_name = format!("{:?}", input.var);
                let destination_name = format!("{:?}", output.var);

                let source_var = if let Some(var) = self.state.get_concolic_var(&source_name) {
                    var.clone()
                } else {
                    self.state.create_concolic_var(&source_name, 0, source_size).clone()
                };

                let destination_var = ConcolicVar::new_from_bv(source_var.concrete, source_var.symbolic);

                println!("---> Load: Source var {} \n", source_name);
                self.state.set_var(&destination_name, destination_var);

                Ok(())
            },
            _ => Err("Error: Load instruction missing output or input".to_string()),
        }
    }


    fn handle_int_carry(&mut self, instruction: &Inst) -> Result<(), String> {
        match (&instruction.output, instruction.inputs.get(0), instruction.inputs.get(1)) {
            (Some(output), Some(input0), Some(input1)) if input0.size == input1.size => {
                let size = input0.size.to_bitvector_size();
                let input0_concrete = self.state.get_concrete_var(&format!("{:?}", input0.var)).unwrap_or_default();
                let input1_concrete = self.state.get_concrete_var(&format!("{:?}", input1.var)).unwrap_or_default();
    
                let bv0 = self.state.create_concolic_var(&format!("{:?}", input0.var), input0_concrete, size).clone();
                let bv1 = self.state.create_concolic_var(&format!("{:?}", input1.var), input1_concrete, size).clone();
    
                let concrete_sum = bv0.concrete.wrapping_add(bv1.concrete);
                let carry_flag = concrete_sum < bv0.concrete || concrete_sum < bv1.concrete;
                self.state.flags.carry_flag = carry_flag;
    
                let symbolic_sum = bv0.symbolic.bvadd(&bv1.symbolic);
                let symbolic_carry_bool = BV::bvugt(&symbolic_sum, &BV::from_u64(self.context, u32::MAX as u64, size));
                let true_bv = BV::from_u64(self.context, 1, 1);
                let false_bv = BV::from_u64(self.context, 0, 1);
                let symbolic_carry_bv = symbolic_carry_bool.ite(&true_bv, &false_bv);
    
                let concrete_carry = if carry_flag { 1 } else { 0 };
                let output_concolic = ConcolicVar::new_from_bv(concrete_carry, symbolic_carry_bv);
    
                self.state.set_var(&format!("{:?}", output.var), output_concolic);
    
                Ok(())
            },
            _ => Err("Error: Inputs for INT_CARRY must be of the same size".to_string()),
        }
    }
        
    // Helper method for zero extension
    fn zero_extend(&self, var: &ConcolicVar<'a>, target_size: u32) -> ConcolicVar<'a> {
        let current_size = var.symbolic.get_size() as u64; // Cast to larger type to avoid overflow
        if current_size < target_size as u64 {
            let extension_size = target_size - current_size as u32; // Safe as target_size is larger
            let extended_symbolic = var.symbolic.zero_ext(extension_size);

            // Use the extended symbolic BV to create the new ConcolicVar
            ConcolicVar::new_from_bv(var.concrete, extended_symbolic)
        } else {
            var.clone()
        }
    }
}


#[cfg(test)]
mod test {
    use z3::ast::BV;
    use z3::Config;
    use parser::parser::{Inst, Opcode, Var, Varnode, Size};
    use super::*;

    #[test]
    fn test_handle_load() {
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

        // Test data
        let input_addr = 100; // Example address
        let output_addr = 200; // Example address
        let input_var = Var::Memory(input_addr);
        let output_var = Var::Memory(output_addr);
        let input_varnode = Varnode { var: input_var, size: Size::Word };
        let output_varnode = Varnode { var: output_var, size: Size::Word };
        let instruction = Inst {
            opcode: Opcode::Load,
            output: Some(output_varnode),
            inputs: vec![input_varnode],
        };

        // Invocation
        executor.handle_load(&instruction).unwrap();

        // Verification
        let source_var_name = format!("{:?}", Var::Memory(input_addr));
        let destination_var_name = format!("{:?}", Var::Memory(output_addr));
        let source_var = executor.state.get_concolic_var(&source_var_name).unwrap().clone();
        let destination_var = executor.state.get_concolic_var(&destination_var_name).unwrap().clone();
        
        assert_eq!(source_var, destination_var, "Load operation did not correctly transfer the variable value");
        assert_eq!(source_var.concrete, destination_var.concrete, "Concrete values should be equal");
        assert!(source_var.symbolic.eq(&destination_var.symbolic), "Symbolic values should be equal");
        
        println!("{:?}", executor);
    }

    #[test]
     fn test_handle_int_carry() {
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

        // Test data
        let input0_value = 4294967295u32; // Max value for a u32, to test carry
        let input1_value = 1u32;
        let input0_var = Var::Memory(100); // Example address
        let input1_var = Var::Memory(200); // Example address
        let output_var = Var::Memory(300); // Example address
        let input0_varnode = Varnode { var: input0_var.clone(), size: Size::Word };
        let input1_varnode = Varnode { var: input1_var.clone(), size: Size::Word };
        let output_varnode = Varnode { var: output_var, size: Size::Byte }; // Size::Byte because carry flag is 1 bit
        let instruction = Inst {
            opcode: Opcode::IntCarry,
            output: Some(output_varnode),
            inputs: vec![input0_varnode, input1_varnode],
        };

        // Create and set initial ConcolicVars
        let bv_input0 = BV::from_u64(&context, input0_value as u64, 32);
        let bv_input1 = BV::from_u64(&context, input1_value as u64, 32);

        let concolic_input0 = ConcolicVar::new_from_bv(input0_value, bv_input0);
        let concolic_input1 = ConcolicVar::new_from_bv(input1_value, bv_input1);

        executor.state.set_var(&format!("{:?}", input0_var), concolic_input0.clone());
        executor.state.set_var(&format!("{:?}", input1_var), concolic_input1.clone());

        println!("Concolic input 0 : {:?}", concolic_input0);
        println!("Concolic input 1 : {:?}", concolic_input1);
        // Invocation
        executor.handle_int_carry(&instruction).unwrap();

        // Verification
        let output_var_name = format!("{:?}", Var::Memory(300));
        let output_var = executor.state.get_concolic_var(&output_var_name).unwrap().clone();
        
        assert_eq!(output_var.concrete, 1, "Carry should be set");
        // Additional assertions ?
        println!("{:?}", executor);
    }
}


