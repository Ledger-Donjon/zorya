// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use z3::{
    ast::{Ast, Bool, Dynamic, BV},
    DeclKind, SatResult, Solver,
};

use crate::concolic::{ConcolicExecutor, Logger};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
            writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

/// Is the given Z3 expression a big number (constant)?
fn is_bnum<'ctx>(expr: &impl Ast<'ctx>) -> bool {
    let Ok(decl) = expr.safe_decl() else {
        return false;
    };
    if decl.kind() != DeclKind::BNUM {
        return false;
    }
    assert!(expr.children().is_empty());
    true
}

/// Is the given Z3 expression an If-Then-Else construction?
fn is_ite<'ctx>(expr: &impl Ast<'ctx>) -> bool {
    let Ok(decl) = expr.safe_decl() else {
        return false;
    };
    decl.kind() == DeclKind::ITE
}

/// Retrieve the constant boolean from a Z3 expression
fn get_constant_bool<'ctx>(expr: &impl Ast<'ctx>) -> Option<bool> {
    let Ok(decl) = expr.safe_decl() else {
        return None;
    };
    match decl.kind() {
        DeclKind::FALSE => Some(false),
        DeclKind::TRUE => Some(true),
        _ => None,
    }
}

/// Simplify a Z3 Dynamic AST in a similar way as
/// https://theory.stanford.edu/~nikolaj/programmingz3.html#sec-subterm-simplification
pub fn simplify_dynamic<'ctx>(expr: &Dynamic<'ctx>) -> Dynamic<'ctx> {
    let Ok(decl) = expr.safe_decl() else {
        // I don't know how this can happen
        todo!();
        // return expr.to_owned()
    };
    let children: Vec<Dynamic<'ctx>> = expr
        .children()
        .iter()
        .map(|x| simplify_dynamic(x))
        .collect();
    if children.is_empty() {
        // There is no sub-expression
        return expr.to_owned();
    }
    // println!("> simpl {:?} {:?}", decl.kind(), children);
    match decl.kind() {
        DeclKind::EQ => {
            let [left, right] = children
                .clone()
                .try_into()
                .expect("Unexpected arguments of EQ");
            if is_ite(&left) && is_bnum(&right) {
                // Transform ITE(cond, t, f) == r into ITE(cond, t == r, f == r)
                let [cond, val_true, val_false] = left.children().try_into().unwrap();
                let cond = cond.as_bool().unwrap();
                let new_val_true = simplify_dynamic(&(val_true._eq(&right)).simplify().into());
                let new_val_false = simplify_dynamic(&(val_false._eq(&right)).simplify().into());
                let new_expr = simplify_dynamic(&cond.ite(&new_val_true, &new_val_false));
                // println!("  => {new_expr}");
                return new_expr;
            }
        }
        DeclKind::ITE => {
            // If-then-else
            let [cond, val_true, val_false] = children.clone().try_into().unwrap();
            if let Some(bool_val_true) = get_constant_bool(&val_true) {
                if let Some(bool_val_false) = get_constant_bool(&val_false) {
                    // Transform ITE(cond, true or false, true or false) into a simpler expression
                    let new_expr = match (bool_val_true, bool_val_false) {
                        (false, false) => val_true,
                        (false, true) => {
                            let cond = cond.as_bool().unwrap();
                            simplify_dynamic(&cond.not().simplify().into())
                        }
                        (true, false) => cond,
                        (true, true) => val_true,
                    };
                    // println!("  => {new_expr}");
                    return new_expr;
                }
            }
        }
        _ => {}
    }
    // Complex conversion of children, cf. https://github.com/prove-rs/z3.rs/issues/351
    decl.apply(
        &children
            .iter()
            .map(|x| x as &dyn Ast<'ctx>)
            .collect::<Vec<_>>(),
    )
}

/// Simplify a Z3 Dynamic AST and prove the result is equivalent to the given expression
pub fn simplify_dynamic_proven<'ctx>(expr: &Dynamic<'ctx>) -> Dynamic<'ctx> {
    let simplified = simplify_dynamic(expr);

    // Prove expr == simplified
    let solver = Solver::new(expr.get_ctx());
    solver.assert(&expr._eq(&simplified).not());
    assert_eq!(solver.check(), SatResult::Unsat);
    return simplified;
}

/// Check if a Z3 expression is an equality
fn is_eq<'ctx>(expr: &impl Ast<'ctx>) -> bool {
    let Ok(decl) = expr.safe_decl() else {
        return false;
    };
    decl.kind() == DeclKind::EQ
}

/// Get constant value from a BV if it's a constant
fn get_constant_bv_value<'ctx>(expr: &BV<'ctx>) -> Option<u64> {
    if is_bnum(expr) {
        expr.as_u64()
    } else {
        None
    }
}

/// Convert a BV to Bool while preserving symbolic information using AST inspection
pub fn bv_to_bool_smart<'ctx>(bv: &BV<'ctx>) -> Bool<'ctx> {
    let ctx = bv.get_ctx();

    // Case 1: Check if it's an ITE expression like (ite condition #x01 #x00)
    if is_ite(bv) {
        if let Some(condition) = extract_condition_from_ite_bv_ast(bv) {
            return condition;
        }
    }

    // Case 2: Check if it's already a simple flag (0 or 1)
    if bv.get_size() == 1 {
        let zero = BV::from_u64(ctx, 0, 1);
        return bv._eq(&zero).not(); // bv != 0
    }

    // Case 3: Fallback - treat as non-zero test
    let zero = BV::from_u64(ctx, 0, bv.get_size());
    bv._eq(&zero).not() // bv != 0
}

/// Extract the underlying condition from an ITE BV expression using AST inspection
fn extract_condition_from_ite_bv_ast<'ctx>(bv: &BV<'ctx>) -> Option<Bool<'ctx>> {
    if !is_ite(bv) {
        return None;
    }

    let children = bv.children();
    if children.len() != 3 {
        return None;
    }

    let condition = children[0].as_bool()?;
    let then_val = children[1].as_bv()?;
    let else_val = children[2].as_bv()?;

    // Check if this is a flag pattern: (ite condition #x01 #x00) or (ite condition #x00 #x01)
    let then_const = get_constant_bv_value(&then_val);
    let else_const = get_constant_bv_value(&else_val);

    match (then_const, else_const) {
        (Some(1), Some(0)) => {
            // Pattern: (ite condition #x01 #x00) - condition is the flag meaning
            Some(condition)
        }
        (Some(0), Some(1)) => {
            // Pattern: (ite condition #x00 #x01) - negated condition is the flag meaning
            Some(condition.not())
        }
        _ => {
            // Not a simple flag pattern, treat as non-zero test
            let zero = BV::from_u64(bv.get_ctx(), 0, bv.get_size());
            Some(bv._eq(&zero).not())
        }
    }
}

/// High-level function to extract the underlying condition from a flag BV using AST inspection
pub fn extract_underlying_condition_from_flag_ast<'ctx>(
    flag_bv: &BV<'ctx>,
    branch_taken: bool,
    logger: &mut Logger,
) -> Bool<'ctx> {
    // Case 1: Handle ITE expressions
    if is_ite(flag_bv) {
        let children = flag_bv.children();
        if children.len() == 3 {
            if let (Some(condition), Some(then_val), Some(else_val)) = (
                children[0].as_bool(),
                children[1].as_bv(),
                children[2].as_bv(),
            ) {
                let then_const = get_constant_bv_value(&then_val);
                let else_const = get_constant_bv_value(&else_val);

                match (then_const, else_const) {
                    (Some(1), Some(0)) => {
                        // Pattern: (ite condition #x01 #x00)
                        // Flag = 1 when condition is true, Flag = 0 when condition is false
                        return if branch_taken {
                            // Branch taken: flag was 1, so condition was true
                            condition
                        } else {
                            // Branch not taken: flag was 0, so condition was false
                            condition.not()
                        };
                    }
                    (Some(0), Some(1)) => {
                        // Pattern: (ite condition #x00 #x01)
                        // Flag = 0 when condition is true, Flag = 1 when condition is false
                        return if branch_taken {
                            // Branch taken: flag was 1, so condition was false
                            condition.not()
                        } else {
                            // Branch not taken: flag was 0, so condition was true
                            condition
                        };
                    }
                    _ => {
                        // Complex ITE, fall through to general handling
                        log!(
                            logger,
                            "DEBUG: Complex ITE pattern - then_const: {:?}, else_const: {:?}",
                            then_const,
                            else_const
                        );
                    }
                }
            } else {
                log!(
                    logger,
                    "DEBUG: Could not extract condition/then/else from ITE"
                );
                log!(
                    logger,
                    "DEBUG: children[0] as_bool: {:?}",
                    children[0].as_bool().is_some()
                );
                log!(
                    logger,
                    "DEBUG: children[1] as_bv: {:?}",
                    children[1].as_bv().is_some()
                );
                log!(
                    logger,
                    "DEBUG: children[2] as_bv: {:?}",
                    children[2].as_bv().is_some()
                );
            }
        } else {
            log!(
                logger,
                "DEBUG: ITE doesn't have 3 children, has: {}",
                children.len()
            );
        }
    } else {
        log!(logger, "DEBUG: Not an ITE expression");
    }

    // Case 2: Handle direct equality comparisons
    if is_eq(flag_bv) {
        let children = flag_bv.children();
        if children.len() == 2 {
            if let (Some(left), Some(right)) = (children[0].as_bv(), children[1].as_bv()) {
                // Check if one side is a constant zero
                if let Some(const_val) = get_constant_bv_value(&right) {
                    if const_val == 0 {
                        // Pattern: (= variable #x00)
                        return if branch_taken {
                            // Branch taken: equality was true, so variable == 0
                            left._eq(&right)
                        } else {
                            // Branch not taken: equality was false, so variable != 0
                            left._eq(&right).not()
                        };
                    }
                }
                if let Some(const_val) = get_constant_bv_value(&left) {
                    if const_val == 0 {
                        // Pattern: (#x00 = variable)
                        return if branch_taken {
                            // Branch taken: equality was true, so variable == 0
                            right._eq(&left)
                        } else {
                            // Branch not taken: equality was false, so variable != 0
                            right._eq(&left).not()
                        };
                    }
                }
            }
        }
    }

    // Case 3: Fallback - use smart BV to Bool conversion
    log!(logger, "DEBUG: Using fallback conversion for flag_bv");
    let condition = bv_to_bool_smart(flag_bv);

    if branch_taken {
        condition
    } else {
        condition.not()
    }
}

/// Convert a Bool to BV while preserving symbolic information
pub fn bool_to_bv_smart<'ctx>(bool_expr: &Bool<'ctx>, target_size: u32) -> BV<'ctx> {
    let ctx = bool_expr.get_ctx();

    // For boolean expressions, use ite to preserve symbolic information
    let one = BV::from_u64(ctx, 1, target_size);
    let zero = BV::from_u64(ctx, 0, target_size);
    bool_expr.ite(&one, &zero)
}

/// Simplify a BV condition by extracting the underlying boolean condition
pub fn simplify_bv_condition<'ctx>(bv: &BV<'ctx>) -> Dynamic<'ctx> {
    // Use the same simplification technique as your existing code
    if is_ite(bv) && is_eq(bv) {
        let children = bv.children();
        if children.len() == 2 {
            let left = &children[0];
            let right = &children[1];

            if is_ite(left) && is_bnum(right) {
                // Transform ITE(cond, t, f) == r into ITE(cond, t == r, f == r)
                let ite_children = left.children();
                if ite_children.len() == 3 {
                    if let Some(cond) = ite_children[0].as_bool() {
                        let val_true = &ite_children[1];
                        let val_false = &ite_children[2];

                        let new_val_true = val_true._eq(right).simplify();
                        let new_val_false = val_false._eq(right).simplify();

                        return cond.ite(&new_val_true, &new_val_false).into();
                    }
                }
            }
        }
    }

    // No simplification possible, return as-is
    bv.clone().into()
}

/// Count the nesting depth of ITEs in an expression
fn count_ite_depth<'ctx>(expr: &impl Ast<'ctx>) -> usize {
    if !is_ite(expr) {
        return 0;
    }

    let children = expr.children();
    if children.len() != 3 {
        return 1;
    }

    let cond_depth = count_ite_depth(&children[0]);
    let then_depth = count_ite_depth(&children[1]);
    let else_depth = count_ite_depth(&children[2]);

    1 + cond_depth.max(then_depth).max(else_depth)
}

/// Break down a complex ITE into simpler constraints using Tseitin transformation
/// Returns (auxiliary_constraints, simplified_result)
fn break_down_ite<'ctx>(
    expr: &Dynamic<'ctx>,
    depth_threshold: usize,
    aux_counter: &mut usize,
) -> (Vec<Bool<'ctx>>, Dynamic<'ctx>) {
    let mut aux_constraints = Vec::new();

    // Check if this is a complex ITE that needs breaking down
    if !is_ite(expr) || count_ite_depth(expr) <= depth_threshold {
        return (aux_constraints, expr.clone());
    }

    let children = expr.children();
    if children.len() != 3 {
        return (aux_constraints, expr.clone());
    }

    let ctx = expr.get_ctx();

    // Recursively break down children first
    let (cond_aux, cond_simplified) = break_down_ite(&children[0], depth_threshold, aux_counter);
    let (then_aux, then_simplified) = break_down_ite(&children[1], depth_threshold, aux_counter);
    let (else_aux, else_simplified) = break_down_ite(&children[2], depth_threshold, aux_counter);

    aux_constraints.extend(cond_aux);
    aux_constraints.extend(then_aux);
    aux_constraints.extend(else_aux);

    // Try to get the condition as Bool
    let cond_bool = if let Some(b) = cond_simplified.as_bool() {
        b
    } else {
        // Can't break down further, return as-is
        return (aux_constraints, expr.clone());
    };

    // Check if then and else branches are compatible
    if let (Some(then_bv), Some(else_bv)) = (then_simplified.as_bv(), else_simplified.as_bv()) {
        // Create auxiliary variable for the ITE result
        let aux_name = format!("ite_aux_{}", aux_counter);
        *aux_counter += 1;

        let aux_var = BV::new_const(ctx, aux_name.as_str(), then_bv.get_size());

        // Add implications: (cond => aux = then) ∧ (¬cond => aux = else)
        aux_constraints.push(cond_bool.implies(&aux_var._eq(&then_bv)));
        aux_constraints.push(cond_bool.not().implies(&aux_var._eq(&else_bv)));

        return (aux_constraints, aux_var.into());
    } else if let (Some(then_bool), Some(else_bool)) =
        (then_simplified.as_bool(), else_simplified.as_bool())
    {
        // Handle boolean ITEs
        let aux_name = format!("ite_aux_bool_{}", aux_counter);
        *aux_counter += 1;

        let aux_var = Bool::new_const(ctx, aux_name.as_str());

        // Add implications: (cond => aux = then) ∧ (¬cond => aux = else)
        aux_constraints.push(cond_bool.implies(&aux_var._eq(&then_bool)));
        aux_constraints.push(cond_bool.not().implies(&aux_var._eq(&else_bool)));

        return (aux_constraints, aux_var.into());
    }

    // Fallback: return the ITE with simplified children
    let result = cond_bool.ite(&then_simplified, &else_simplified);
    (aux_constraints, result)
}

/// Displays constraints and simplifies them with Z3 and custom simplifier
pub fn add_constraints_from_vector<'ctx>(executor: &ConcolicExecutor<'ctx>) {
    let logger = &mut executor.state.logger.clone();
    log!(logger, "=== CONSTRAINT ANALYSIS ===");

    let assertions = executor.constraint_vector.clone();

    //log!(logger, "=== Z3 SIMPLIFIED CONSTRAINTS ===");
    // Display and collect Z3 simplified constraints
    let mut z3_simplified_constraints = Vec::new();
    for (_i, constraint) in assertions.iter().enumerate() {
        let z3_simplified = constraint.simplify();
        // log!(
        //     logger,
        //     "Constraint #{} (Bool) Simplified with Z3: {:?}",
        //     i + 1,
        //     z3_simplified
        // );
        z3_simplified_constraints.push(z3_simplified);
    }

    log!(logger, "=== CUSTOM SIMPLIFIED CONSTRAINTS ===");
    // Display and collect custom simplified constraints
    let mut custom_simplified_constraints = Vec::new();
    let mut aux_counter = 0;

    for (i, z3_simplified) in z3_simplified_constraints.iter().enumerate() {
        let custom_simplified = simplify_dynamic(&Dynamic::from(z3_simplified));

        // Check ITE depth and break down if too complex
        let ite_depth = count_ite_depth(&custom_simplified);
        if ite_depth > 2 {
            log!(
                logger,
                "Constraint #{} has ITE depth {}, breaking down...",
                i + 1,
                ite_depth
            );

            // Break down the constraint
            let (aux_constraints, simplified_result) =
                break_down_ite(&custom_simplified, 2, &mut aux_counter);

            log!(
                logger,
                "Constraint #{} (Bool) broken into {} auxiliary constraints",
                i + 1,
                aux_constraints.len()
            );

            // Add auxiliary constraints
            for (j, aux_constraint) in aux_constraints.iter().enumerate() {
                log!(
                    logger,
                    "  Auxiliary constraint #{}.{}: {}",
                    i + 1,
                    j + 1,
                    aux_constraint
                );
                custom_simplified_constraints.push(aux_constraint.clone());
            }

            // Add the main simplified constraint
            if let Some(bool_constraint) = simplified_result.as_bool() {
                log!(
                    logger,
                    "Constraint #{} (Bool) with Custom Simplification: {}",
                    i + 1,
                    bool_constraint
                );
                custom_simplified_constraints.push(bool_constraint);
            } else {
                log!(
                    logger,
                    "WARNING: Broken down constraint #{} is not Bool, using original",
                    i + 1
                );
                log!(
                    logger,
                    "Constraint #{} (Bool) with Custom Simplification: {}",
                    i + 1,
                    custom_simplified
                );
                if let Some(bool_constraint) = custom_simplified.as_bool() {
                    custom_simplified_constraints.push(bool_constraint);
                }
            }
        } else {
            log!(
                logger,
                "Constraint #{} (Bool) with Custom Simplification: {}",
                i + 1,
                custom_simplified
            );

            // Try to use the simplified Bool directly
            match custom_simplified.as_bool() {
                Some(bool_constraint) => {
                    custom_simplified_constraints.push(bool_constraint);
                }
                None => {
                    log!(
                        logger,
                        "WARNING: Cannot convert constraint #{} to Bool, using original",
                        i + 1
                    );
                    // Try to convert Dynamic to Bool, fallback to panic if not possible
                    match custom_simplified.as_bool() {
                        Some(bool_constraint) => {
                            custom_simplified_constraints.push(bool_constraint);
                        }
                        None => {
                            panic!(
                                "Constraint #{} could not be converted to Bool for solver assertion.",
                                i + 1
                            );
                        }
                    }
                }
            }
        }
    }

    log!(logger, "=== ASSERTING SIMPLIFIED CONSTRAINTS TO SOLVER ===");

    // Assert the custom simplified constraints to the solver
    log!(
        logger,
        "Adding {} simplified constraints to solver...",
        custom_simplified_constraints.len()
    );
    for simplified_constraint in custom_simplified_constraints.iter() {
        executor.solver.assert(simplified_constraint);
    }

    log!(logger, "=== END CONSTRAINT ANALYSIS ===");
}

#[cfg(test)]
mod tests {
    use z3::{Config, Context};

    use super::*;

    #[test]
    fn test_simplify_constraint() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let bit_0 = BV::from_u64(&ctx, 0, 1);
        let bit_1 = BV::from_u64(&ctx, 1, 1);
        let u8_0 = BV::from_u64(&ctx, 0, 8);
        let u8_1 = BV::from_u64(&ctx, 1, 8);
        let u64_0 = BV::from_u64(&ctx, 0, 64);
        let x = BV::new_const(&ctx, "x", 64);

        // Test simplifying (ite (= (ite (= indices_len_R9!259 #x0000000000000000) #x01 #x00) #x00) #b1 #b0)
        let expr = x
            ._eq(&u64_0)
            .ite(&u8_1, &u8_0)
            ._eq(&u8_0)
            .ite(&bit_1, &bit_0);
        println!("expr: {expr}");
        assert_eq!(
            expr.to_string(),
            "(ite (= (ite (= x #x0000000000000000) #x01 #x00) #x00) #b1 #b0)"
        );

        let expr_simpl = expr.simplify();
        println!("simplified: {expr_simpl}");
        assert_eq!(expr.to_string(), expr_simpl.to_string()); // No change

        let expr_simpl = simplify_dynamic(&expr.clone().into()).as_bv().unwrap();
        println!("simplified2: {expr_simpl}");
        assert_eq!(
            expr_simpl.to_string(),
            "(ite (not (= x #x0000000000000000)) #b1 #b0)"
        );

        // Prove expr == expr_simpl
        let solver = Solver::new(&ctx);
        solver.assert(&expr._eq(&expr_simpl).not());
        assert_eq!(solver.check(), SatResult::Unsat);

        // Use simplify_dynamic_proven directly
        let expr_simpl2 = simplify_dynamic_proven(&expr.clone().into())
            .as_bv()
            .unwrap();
        assert_eq!(expr_simpl, expr_simpl2);
    }
}
