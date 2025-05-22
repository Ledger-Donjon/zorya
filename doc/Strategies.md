# Strategies for Finding Bugs, Panics, and Vulnerabilities with Zorya

Zorya is a **concolic execution engine** that can explore execution paths of a binary or a specific function by combining concrete and symbolic execution. It works at the level of Ghidra’s P-Code intermediate representation, executing P-Code instructions concolically to reason about both concrete values and symbolic constraints.

Below is an example of Ghidra’s P-Code view alongside the corresponding Intel instruction:

<div align="left">
  <img src="pcode-ghidra.png" alt="Ghidra P-Code vs. Intel Instruction" width="600"/>
</div>


> **CMPXCHG (Intel)**  
> Compares the value in AL/AX/EAX/RAX with the first operand.  
> - If equal, loads the second operand into the destination.  
> - Otherwise, loads the destination into AL/AX/EAX/RAX.  
> *(RAX is 64-bit only.)*


## Strategy 1: Direct Panic Detection

**Goal:** Identify if the given concrete inputs cause an immediate panic during the normal execution flow.

**What Happens:** Zorya runs the binary concolically along the single path determined by your inputs, reports any panic or crash observed.


## Strategy 2: Binary-Argument Symbolic Exploration

**Goal:** Find new command-line arguments that lead to a panic.

1. **Entrypoint Selection**  
   - Default: `__start` → symbolic `argc`, `argv`  
   - Go binaries: `main.main` → symbolic `os.Args`  
2. **Symbolic Lifting**  
   - Transform all command-line arguments into fresh symbolic variables.  
3. **Concolic execution & Speculative exploration**  
   - Each P-Code instruction is executed concolically: the concrete value drives the execution path, while symbolic expressions collect constraints.  
   - At every conditional branch (`CBranch`), Zorya can **speculate** on the untaken path up to a configurable **`max_depth`** (default: 10 AST nodes).  
   - If the speculative path can reach a panic or other target, Zorya asks the SMT solver (Z3) for concrete inputs that satisfy the collected constraints.  
4. **SMT Solving**  
   - If a branch reaches a panic target, invoke Z3 to solve for concrete `argv` or `os.Args` values.


## Strategy 3: Function-Argument Symbolic Exploration

**Goal:** Discover function inputs that trigger a panic inside a specific function.

1. **Function Selection & Signature Analysis**  
   - Choose the address of the fucntion where to start the analysis -> Zorya reads the function signature to locate argument registers or stack slots.
2. **Symbolic Lifting**  
   - Convert each function argument into a fresh symbolic variable according to its type.  
3. **Concolic execution & Speculative exploration**  
   - Execute the function concolically, speculatively exploring untaken branches (up to `max_depth`).  
4. **SMT Solving**  
   - When a speculative path reaches a panic site, Z3 computes concrete argument values that force that path.


<div align="left">
  <img src="github_zorya_panic-exploration_strategies.png" alt="Strategies" width="1000"/>
</div>

### Tips for Effective Analysis

- **Start Simple:** First run Strategy 1 with concrete inputs to catch obvious panics.  
- **Incremental Depth:** If the execution is too long, lower ```max-depth``` to focus on the most promising conditions.  
- **Targeted Functions:** Use Strategy 3 on small, security-critical functions to reduce state space.  
- **Combine with Fuzzing:** Use Zorya to generate crash-triggering inputs, then feed them to a coverage-guided fuzzer for further exploration.


*Happy bug hunting with Zorya!*  