use crate::state::State;
use parser::parser::{Inst, Opcode};
use z3::{Context, Solver};
use crate::concolic::ConcolicVar;

/// Represents the concolic executor
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
            Opcode::IntSCarry => self.handle_int_scarry(instruction),
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
        }
    }

    fn handle_load(&mut self, instruction: &Inst) {
        if let (Some(output), Some(input)) = (&instruction.output, instruction.inputs.get(0)) {
            let source_size = input.size.to_bitvector_size();
            let source_name = format!("{:?}", input.var);
            let destination_name = format!("{:?}", output.var);

            let source_var = self.state.get_or_create_concolic_var(&source_name, source_size);
            println!("---> Load: Source var {} \n", source_name);
            self.state.set_var(&destination_name, source_var);
        } else {
            println!("Error: Load instruction missing output or input");
        }
    }

    fn handle_int_carry(&mut self, instruction: &Inst) {
        if let Some(output) = &instruction.output {
            if instruction.inputs.len() >= 2 {
                let operand1_name = format!("{:?}", instruction.inputs[0].var);
                let operand2_name = format!("{:?}", instruction.inputs[1].var);
                let output_name = format!("{:?}", output.var);

                let op1_var = self.state.get_or_create_concolic_var(&operand1_name, instruction.inputs[0].size.to_bitvector_size());
                let op2_var = self.state.get_or_create_concolic_var(&operand2_name, instruction.inputs[1].size.to_bitvector_size());
                println!("---> IntCarry Operand 1 var {}", operand1_name);
                println!("---> IntCarry Operand 2 var {} \n", operand2_name);

                let max_size = std::cmp::max(op1_var.symbolic.get_size(), op2_var.symbolic.get_size());
                let mut op1_var_extended = self.zero_extend(&op1_var, max_size);
                let op2_var_extended = self.zero_extend(&op2_var, max_size);

                op1_var_extended.add(&op2_var_extended, self.context);

                let carry_flag = self.state.calculate_carry(&op1_var_extended, &op2_var_extended, max_size);
                self.state.set_flag(|flags| flags.set_carry_flag(carry_flag));

                self.state.set_var(&output_name, op1_var_extended);
            } else {
                println!("Error: IntCarry instruction missing input operands");
            }
        } else {
            println!("Error: IntCarry instruction missing output");
        }
    }

    fn handle_int_scarry(&mut self, instruction: &Inst) {
        if let Some(output) = &instruction.output {
            if instruction.inputs.len() >= 2 {
                let operand1_name = format!("{:?}", instruction.inputs[0].var);
                let operand2_name = format!("{:?}", instruction.inputs[1].var);
                let output_name = format!("{:?}", output.var);

                let op1_var = self.state.get_or_create_concolic_var(&operand1_name, instruction.inputs[0].size.to_bitvector_size());
                let op2_var = self.state.get_or_create_concolic_var(&operand2_name, instruction.inputs[1].size.to_bitvector_size());
                println!("---> IntCarry Operand 1 var {}", operand1_name);
                println!("---> IntCarry Operand 2 var {} \n", operand2_name);

                let max_size = std::cmp::max(op1_var.symbolic.get_size(), op2_var.symbolic.get_size());
                let mut op1_var_extended = self.zero_extend(&op1_var, max_size);
                let op2_var_extended = self.zero_extend(&op2_var, max_size);

                op1_var_extended.add(&op2_var_extended, self.context);

                let carry_flag = self.state.calculate_signed_carry(&op1_var_extended, &op2_var_extended);
                self.state.set_flag(|flags| flags.set_carry_flag(carry_flag));

                self.state.set_var(&output_name, op1_var_extended);
            } else {
                println!("Error: IntCarry instruction missing input operands");
            }
        } else {
            println!("Error: IntCarry instruction missing output");
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
