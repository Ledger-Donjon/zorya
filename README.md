<div align="center">
  <img src="doc/zorya_logo.jpg" alt="Logo" width="300"/>
</div>

<br><br>
Zorya is a **concolic execution framework** designed to detect **logic-related bugs, language-specific vulnerabilities, and identify new patterns of security issues mainly in Go binaries**. The analysis begins by generating CPU register and memory dumps using ```gdb```. Zorya loads these dumps to initialize execution from a specified starting address, ensuring a realistic and accurate representation of the program state.

The core methodology involves **translating binary code into Ghidra's raw P-Code**, a low-level intermediate representation, which is subsequently parsed for precise execution path analysis. Other programs like C programs can also be translated to P-Code.

Zorya's engine, implemented in Rust, uses the **Z3 SMT solver** and includes a state manager, CPU state, memory model, and virtual file system. It emulates P-Code instructions to track the execution and detect vulnerabilities in the analyzed binaries.

Zorya supports both concrete and symbolic data types, x86-64 instructions and syscalls, and manages the program counter. Currently, Zorya analyzes single-threaded Go programs compiled with TinyGo, with plans to address multithreading and goroutines in future work.

## :inbox_tray: Install
Make sure to have Rust, Golang and Python properly installed.

```
git clone --recursive https://github.com/kajaaz/zorya.git
cd zorya
make all
```

## :wrench: Usage

### A. Interactive Usage (prefered)
Zorya provides a guided mode, so you don't need to remember the options or flags. It prompts you with questions to outline three typical scenarios:

- Standard Execution - Automatically detects the main function or entry point.
- Function-Specific Execution - Allows selecting and providing arguments for a specific function.
- Custom Execution - Lets you manually input an address and arguments for targeted analysis.

Given the absolute path to the binary you want to analyze ```<path>```, simply run:
```
zorya <path>
```
The prompt will ask you for the:
1. Source code language: go, c, or c++
2. Go compiler: tinygo or gc (only when go is selected)
3. Analysis mode: start, main, function, or custom
4. Function address: If you chose function or custom modes
5. Binary arguments: If the binary expects arguments (optional)

### B. Basic Command-Line Usage
To use Zorya in its basic form, you need the absolute path to the binary you wish to analyze (```<path>```) and the hexadecimal address where execution should begin (```<addr>```). You must then specify the execution mode (start, main, function, or custom) based on your chosen analysis strategy. Additionally, you can provide any necessary arguments to be passed to the binary:
```
zorya <path> --lang <go|c|c++> [--compiler <tinygo|gc>] --mode <start|main|function|custom> <addr> --arg <arg1> <arg2>

FLAG:
    --lang         Specifies the language used in the source code (go/c/c++)
    --compiler     When Go was chosen as 'lang', specifies the used compiler (tinygo or gc)
    --mode         Specifies the strategy mode to determine the starting address for binary analysis. Options include:
                      start → Use the binary's entry point
                      main → Analyze the main function (main.main preferred in Go binaries)
                      function → Specify a function address manually
                      custom → Define an arbitrary execution address

OPTION:
    --arg          Specifies arguments to pass to the binary, if any (default is 'none').
```

Notes:
- If any flag is missing, Zorya will prompt you interactively to ask for it.
- The address ()```<addr>```) is mandatory when using function or custom modes.
- Arguments (--arg) are optional.

## How to build your binary?
Zorya needs the binary to have the debug symbols to perform the complete analysis. Striped binaries could be also analyzed, but it required to disable many functionnalities of the tool.

For Go:
- ```tinygo build -gc=conservative -opt=0 .```
- ```go build -gcflags=all="-N -l" .```

## :mag_right: Try it out with our test binaries
You can run Zorya on precompiled binaries with TinyGo located in ```tests/programs```.
All the execution results can be found in ```results```, except the P-Code file which is in ```external/pcode-generator/results```.

```
$ zorya /absolute/path/to/zorya/tests/programs/crashme/crashme


███████╗ ██████╗ ██████╗ ██╗   ██╗ █████╗ 
╚══███╔╝██╔═══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗
  ███╔╝ ██║   ██║██████╔╝ ╚████╔╝ ███████║
 ███╔╝  ██║   ██║██╔══██╗  ╚██╔╝  ██╔══██║
███████╗╚██████╔╝██║  ██║   ██║   ██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
    Next Generation Concolic Analysis

What is the source language of the binary? (go, c or c++)
[go]: 

Which Go compiler was used to build the binary? (tinygo / gc)
[tinygo]: 
***********************************************************************

Where to begin the analysis? (start / main / function / custom)
[main]: 

Automatically detected main function address: 0x000000000022b1d0
***********************************************************************

Does the binary expect any arguments? (none / e.g., x y z)
[none]: a

***********************************************************************
Running command: /home/kgorna/Documents/zorya/zorya /home/kgorna/Documents/zorya/tests/programs/crashme/crashme --mode main 0x000000000022b1d0 --lang go --compiler tinygo --arg a
...
```


## :books: Deep dive inside

### Architecture
- Implement a concolic execution engine (concrete and symbolic) written in Rust,
- Uses Ghidra’s P-Code as Intermediate Representation (IR),
- Has an internal structure based on an AMD64 CPU and a virtual file system.

### Internal Structure
- Implement concolically most of the P-Code opcodes (see ```executor_[int|float|bool].rs```),
- Implement concolically common syscalls and CPU instructions (see ```executor_callother.rs``` and ```executor_callother_syscalls.rs```),
- Has an integrated handling of the generation and parsing of P-Code (see ```pcode-generator``` and ```pcode-parser```),
- Has a mechanism to get and set the value of AMD64 registers and sub-registers - i.e. for instance, get only the specific bytes of a full register (see ```cpu_state.rs```).

### Functionnalities
- Can generate a file with the detailed logs of the execution of each instruction (see ```execution_log.txt```),
- Can generate a file with the names of the executed functions (see ```execution_trace.txt```),
- Can analyse the concolic handling of the jump tables, a specific type of switch tables that replace binary search by more efficient jumping mechanism for close number labels (see ```jump_table.json```),
- Can generate a file witht the cross-reference addresses leading to all the panic functions that are in the target binary (see ```xref_addresses.txt```),
- Is able to translate the executable part of libc.so and ld-linux-x86-64.so as P-Code after its dynamic loading.

### Invariants writing
- Has integrated Z3 capabilities for writing invariants over the instructions and CPU registers, through the Rust crate.

### Strategies to find bugs/panics/vuln
For more explanation about the bugs/panics/vuln research strategies, read here : [Strategies.md](doc/Strategies.md).
<div align="left">
  <img src="doc/github_zorya_panic-exploration_strategies.png" alt="Strategies" width="1000"/>
</div>


## :movie_camera: Demo video
Incoming

## :spiral_calendar: Roadmap 
Zorya has been developeped and tested for now on Linux Ubuntu as the execution environement with x86-64 binaries targets. The roadmap below details the features that have been added over time and those that are planned:
<div align="left">
  <img src="doc/github_roadmap-zorya_may-2025.png" alt="Roadmap" width="900"/>
</div>

## :memo: Academic work
Incoming

## Troubleshooting
When building the project, if you have issues related to C++, it might be necessary to also specify the path to ```libclang.so```:
```
sudo locate libclang.so
export LIBCLANG_PATH=/path/to/lib/libclang.so
```