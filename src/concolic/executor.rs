use crate::state::State;
use super::concolic_var::ConcolicVar;
use parser::parser::{Inst, Opcode};
use z3::{Context, Solver};

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
        let source_name = format!("{:?}", instruction.inputs[0].var);
        let destination_name = format!("{:?}", instruction.output.as_ref().unwrap().var);

        let source_var = self.state.get_or_create_concolic_var(&source_name, 32);
        self.state.set_var(&destination_name, source_var);
    }

    fn handle_int_carry(&mut self, instruction: &Inst) {
        let operand1_name = format!("{:?}", instruction.inputs[0].var);
        let operand2_name = format!("{:?}", instruction.inputs[1].var);
        let output_name = format!("{:?}", instruction.output.as_ref().unwrap().var);

        let mut op1_var = self.state.get_or_create_concolic_var(&operand1_name, 32);
        let op2_var = self.state.get_or_create_concolic_var(&operand2_name, 32);
        // Perform the addition. Assuming `add` modifies op1_var in place
        op1_var.add(&op2_var, &self.context);

        // Determine if a carry occurred. Carry occurs if the result is smaller than any of the operands
        let carry_flag = op1_var.concrete < op1_var.concrete.wrapping_add(op2_var.concrete);

        // Update the state with the result and the carry flag
        self.state.set_var(&output_name, op1_var);
        self.state.set_flag(|flags| flags.set_carry_flag(carry_flag));

    }

    fn handle_int_scarry(&mut self, instruction: &Inst) {
        let operand1_name = format!("{:?}", instruction.inputs[0].var);
        let operand2_name = format!("{:?}", instruction.inputs[1].var);
        let output_name = format!("{:?}", instruction.output.as_ref().unwrap().var);

        let op1_var = self.state.get_or_create_concolic_var(&operand1_name, 32);
        let op2_var = self.state.get_or_create_concolic_var(&operand2_name, 32);

        // Calculate the signed addition and check for overflow
        let (result, signed_overflow) = op1_var.concrete.overflowing_add(op2_var.concrete);

        // Update the result variable
        let result_var = ConcolicVar::new(result, &output_name, &self.context, 32);
        self.state.set_var(&output_name, result_var);

        // Update the state with the signed carry flag
        self.state.set_flag(|flags| flags.set_carry_flag(signed_overflow));
    }

}
