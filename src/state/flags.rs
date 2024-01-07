#[derive(Default, Debug)]
pub struct Flags {
    pub zero_flag: bool,       // Set if the result is zero
    pub sign_flag: bool,       // Set if the result is negative
    pub carry_flag: bool,      // Set if there's an overflow out of the most significant bit (for unsigned operations)
    pub overflow_flag: bool,   // Set if there's an overflow out of the most significant bit (for signed operations)
    pub parity_flag: bool,     // Set if the number of set bits is even
}

impl Flags {
    pub fn set_zero_flag(&mut self, value: bool) {
        self.zero_flag = value;
    }

    pub fn set_sign_flag(&mut self, value: bool) {
        self.sign_flag = value;
    }

    pub fn set_carry_flag(&mut self, value: bool) {
        self.carry_flag = value;
    }

    pub fn set_overflow_flag(&mut self, value: bool) {
        self.overflow_flag = value;
    }

    pub fn set_parity_flag(&mut self, value: bool) {
        self.parity_flag = value;
    }
}