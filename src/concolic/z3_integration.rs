use z3::{ast::{Bool, BV}, Config, Context, Model, SatResult, Symbol, Solver};

pub struct Z3Integration {
    context: Context,
}

impl Z3Integration {
    pub fn new() -> Self {
        let config = Config::new();
        let context = Context::new(&config);

        Z3Integration {
            context,
        }
    }

    pub fn create_symbolic_var<'a>(&'a self, name: &str, bitvector_size: u32) -> BV<'a> {
        BV::new_const(&self.context, Symbol::String(name.to_string()), bitvector_size)
    }

    pub fn add_constraint<'a>(&'a self, constraint: Bool<'a>) {
        let solver = Solver::new(&self.context);
        solver.assert(&constraint);
    }

    pub fn check_sat(&self) -> bool {
        let solver = Solver::new(&self.context);
        solver.check() == SatResult::Sat
    }

    pub fn get_model<'a>(&'a self) -> Option<Model<'a>> {
        let solver = Solver::new(&self.context);
        if solver.check() == SatResult::Sat {
            Some(solver.get_model().unwrap())
        } else {
            None
        }
    }

    // Additional utility functions ?
}
