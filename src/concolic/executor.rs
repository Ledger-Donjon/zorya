use crate::state::State;
use parser::parser::{Inst, Opcode, Var, Size, Varnode};
use z3::{Context, Solver};
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

    pub fn execute_instruction(&mut self, instruction: Inst) {
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


    pub fn handle_load(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }

        // Resolve the offset
        let offset = match instruction.inputs[1].var {
            Var::Register(reg) | Var::Unique(reg) => reg,
            _ => return Err("Input1 must be a Register or Unique type for offset".to_string()),
        };

        // Read the value from the resolved address
        let value = match instruction.output.as_ref().unwrap().size {
            Size::Quad => self.state.memory.read_quad(offset).map_err(|e| e.to_string())?,
            Size::Word => u64::from(self.state.memory.read_word(offset).map_err(|e| e.to_string())?),
            Size::Half => u64::from(self.state.memory.read_half(offset).map_err(|e| e.to_string())?),
            Size::Byte => u64::from(self.state.memory.read_byte(offset).map_err(|e| e.to_string())?),
        };

        // Create a new concolic variable with the read value and add it to the state
        let concolic_value = ConcolicVar::new(value as u32, &format!("{:?}", instruction.output.clone().unwrap().var), self.context, instruction.output.clone().clone().unwrap().size.to_bitvector_size());
        self.state.set_var(&format!("{:?}", instruction.output.clone().unwrap().var), concolic_value);

        // Only create a new concolic variable if it doesn't already exist
        let var_name = format!("{:?}", instruction.output.clone().unwrap().var);
        if !self.state.concolic_vars.contains_key(&var_name) {
            let concolic_value = ConcolicVar::new(value as u32, &var_name, self.context, instruction.output.clone().unwrap().size.to_bitvector_size());
            self.state.set_var(&var_name, concolic_value);
        }

        Ok(())
    }


    pub fn handle_int_carry(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_CARRY".to_string());
        }

        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_CARRY".to_string());
        }

        let input0 = &instruction.inputs[0];
        let input1 = &instruction.inputs[1];

        if input0.size != input1.size {
            return Err("Inputs must be the same size for INT_CARRY".to_string());
        }

        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;

        // Ensure that the values are treated as u32
        let value0_u32 = value0 as u32;
        let value1_u32 = value1 as u32;

        // Check for carry for u32 values. The sum is cast to u64 to avoid overflow
        let carry = (value0_u32 as u64 + value1_u32 as u64) > 0xFFFFFFFF;

        // Store the result of the carry condition
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.set_var(&result_var_name, ConcolicVar::new(carry as u32, &result_var_name, self.context, 1));

        Ok(())
    }

    fn initialize_var_if_absent(&mut self, varnode: &Varnode) -> Result<u32, String> {
        match self.state.get_concrete_var(varnode) {
            Ok(val) => Ok(val),
            Err(_) => {
                let initial_value = 0; // Initial value
                let var_name = format!("{:?}", varnode.var);
                let concolic_value = ConcolicVar::new(initial_value, &var_name, self.context, varnode.size.to_bitvector_size());
                self.state.set_var(&var_name, concolic_value);
                Ok(initial_value)
            }
        }
    }
    
    #[allow(dead_code)]
    // Helper method for zero extension
    fn zero_extend(&self, var: &ConcolicVar<'a>, target_size: u32) -> ConcolicVar<'a> {
        let current_size = var.symbolic.get_size() as u64; // Cast to larger type to avoid overflow
        if current_size < target_size as u64 {
            let extension_size = target_size - current_size as u32; // Safe as target_size is larger
            let extended_symbolic = var.symbolic.zero_ext(extension_size);

            // Create a new ConcolicVar
            ConcolicVar::new_from_bv(var.concrete, extended_symbolic)
        } else {
            var.clone()
        }
    }
}

