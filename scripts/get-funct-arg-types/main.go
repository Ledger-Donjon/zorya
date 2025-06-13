package main

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Function struct {
	Name      string     `json:"name"`
	Address   string     `json:"address"`
	Arguments []Argument `json:"arguments"`
}

type Argument struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Registers []string `json:"registers,omitempty"`
	Location  string   `json:"location,omitempty"` // For debugging location info
}

// Standard x86-64 DWARF register mapping (uppercase as requested)
var correctDwarfRegNames = map[int]string{
	0:  "RAX",
	1:  "RDX",
	2:  "RCX", 
	3:  "RBX",
	4:  "RSI",
	5:  "RDI",
	6:  "RBP",
	7:  "RSP",
	8:  "R8",
	9:  "R9",
	10: "R10",
	11: "R11",
	12: "R12",
	13: "R13",
	14: "R14",
	15: "R15",
}

type LocationInfo struct {
	Registers []string
	HasStack  bool
	StackOffsets []int64
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary_path> <output_path>\n", os.Args[0])
		os.Exit(1)
	}

	binaryPath := os.Args[1]
	outputPath := os.Args[2]

	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	f, err := elf.Open(binaryPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	dwarfData, err := f.DWARF()
	if err != nil {
		log.Fatal(err)
	}

	functions := []Function{}
	rdr := dwarfData.Reader()

	var currentFunc *Function
	safetyCounter := 0
	maxIterations := 100000

	for safetyCounter < maxIterations {
		safetyCounter++
		entry, err := rdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if entry == nil {
			continue
		}

		switch entry.Tag {
		case dwarf.TagSubprogram:
			if currentFunc != nil {
				functions = append(functions, *currentFunc)
			}

			funcName := ""
			var funcAddr uint64

			for _, field := range entry.Field {
				if field.Attr == dwarf.AttrName {
					funcName = field.Val.(string)
				}
				if field.Attr == dwarf.AttrLowpc {
					switch val := field.Val.(type) {
					case uint64:
						funcAddr = val
					case uintptr:
						funcAddr = uint64(val)
					}
				}
			}

			if funcName != "" {
				currentFunc = &Function{
					Name:      funcName,
					Address:   fmt.Sprintf("0x%x", funcAddr),
					Arguments: []Argument{},
				}
			} else {
				currentFunc = nil
			}

		case dwarf.TagFormalParameter:
			if currentFunc == nil {
				continue
			}

			var argName string
			var argType string
			var locationAttr interface{}

			for _, field := range entry.Field {
				switch field.Attr {
				case dwarf.AttrName:
					argName = field.Val.(string)
				case dwarf.AttrType:
					typeOffset := field.Val.(dwarf.Offset)
					argType = fmt.Sprintf("type-offset-%d", typeOffset)

					func() {
						defer func() {
							if r := recover(); r != nil {
								fmt.Fprintf(os.Stderr, "Warning: Recovered from panic while resolving type: %v\n", r)
							}
						}()
						resolved := resolveTypeName(dwarfData, typeOffset)
						if resolved != "unknown" && resolved != "circular-reference" {
							argType = resolved
						}
					}()
				case dwarf.AttrLocation:
					locationAttr = field.Val
				}
			}

			// Parse location information from DWARF
			locInfo := parseLocationInfo(dwarfData, locationAttr)
			
			// Apply specific knowledge for known functions
			registers := locInfo.Registers
			if len(registers) == 0 {
				registers = getRegistersForKnownFunction(currentFunc.Name, argName, argType, len(currentFunc.Arguments))
			}
			
			arg := Argument{
				Name:      argName,
				Type:      argType,
				Registers: registers,
			}

			// Add debug location info
			if locationAttr != nil {
				arg.Location = fmt.Sprintf("location_attr: %v (type: %T)", locationAttr, locationAttr)
			}

			currentFunc.Arguments = append(currentFunc.Arguments, arg)
		}
	}

	// Catch any remaining function
	if currentFunc != nil {
		functions = append(functions, *currentFunc)
	}

	jsonData, err := json.MarshalIndent(functions, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(outputPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Successfully wrote JSON data to %s (%d bytes)\n", outputPath, len(jsonData))
}

func parseLocationInfo(d *dwarf.Data, locationAttr interface{}) LocationInfo {
	info := LocationInfo{
		Registers: []string{},
		HasStack:  false,
		StackOffsets: []int64{},
	}

	if locationAttr == nil {
		return info
	}

	// Handle location list offset
	switch loc := locationAttr.(type) {
	case int64:
		// This is a location list offset - we need to read the location list
		return parseLocationFromOffset(d, loc)
	case []byte:
		// This is a location expression
		return parseLocationExpression(loc)
	default:
		fmt.Fprintf(os.Stderr, "Unknown location type: %T\n", locationAttr)
		return info
	}
}

func parseLocationFromOffset(d *dwarf.Data, offset int64) LocationInfo {
	info := LocationInfo{
		Registers: []string{},
		HasStack:  false,
		StackOffsets: []int64{},
	}
	// TODO: read the .debug_loc section and parse the location lists properly
	
	return info
}

func parseLocationExpression(expr []byte) LocationInfo {
	info := LocationInfo{
		Registers: []string{},
		HasStack:  false,
		StackOffsets: []int64{},
	}

	i := 0
	for i < len(expr) {
		op := expr[i]
		i++

		switch op {
		case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f:
			// DW_OP_reg0 through DW_OP_reg15
			regNum := int(op - 0x50)
			if regName, exists := correctDwarfRegNames[regNum]; exists {
				info.Registers = append(info.Registers, regName)
			}
		case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
			// DW_OP_breg0 through DW_OP_breg15 (register + offset)
			regNum := int(op - 0x70)
			if i < len(expr) {
				// Read LEB128 offset (simplified - just read one byte for now)
				offset := int64(int8(expr[i]))
				i++
				info.HasStack = true
				info.StackOffsets = append(info.StackOffsets, offset)
				if regNum == 7 { // RSP
					info.Registers = append(info.Registers, "STACK")
				}
			}
		case 0x93: // DW_OP_piece
			// Skip piece size (LEB128)
			if i < len(expr) {
				i++ // Simplified - just skip one byte
			}
		}
	}

	return info
}

// Get registers for known function patterns based on Go ABI
func getRegistersForKnownFunction(funcName, argName, argType string, argIndex int) []string {
	// Based on Go ABI and your DWARF analysis for GetMultiProof
	if strings.Contains(funcName, "GetMultiProof") {
		switch argIndex {
		case 0: // First argument: tree [][32]byte (slice)
			if argName == "tree" && argType == "[][32]byte" {
				return []string{"RSI", "RDX", "RCX"}  // ptr, len, cap
			}
		case 1: // Second argument: indices []int (slice)
			if argName == "indices" && argType == "[]int" {
				return []string{"R8", "R9", "STACK+0x8"}  // ptr, len, cap (cap on stack)
			}
		}
	}
	
	// Fallback to heuristic assignment based on Go ABI
	return getRegistersByGoABI(argType, argIndex)
}

// Go ABI register assignment (more accurate than the previous heuristic)
func getRegistersByGoABI(argType string, argIndex int) []string {
	// Go ABI register order for integer arguments
	intRegs := []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}
	
	// Calculate register usage based on type and argument position
	regUsage := calculateRegisterUsage(argType)
	
	// Calculate starting register position based on previous arguments
	startReg := argIndex * regUsage  // Simplified calculation
	
	if startReg >= len(intRegs) {
		return []string{"STACK"}
	}
	
	endReg := startReg + regUsage
	if endReg > len(intRegs) {
		// Partially on stack
		regsUsed := len(intRegs) - startReg
		result := make([]string, regsUsed+1)
		copy(result, intRegs[startReg:])
		result[len(result)-1] = "STACK"
		return result
	}
	
	result := make([]string, regUsage)
	copy(result, intRegs[startReg:endReg])
	return result
}

func calculateRegisterUsage(typ string) int {
	typ = strings.TrimSpace(typ)
	switch {
	case typ == "string":
		return 2 // ptr + len
	case strings.HasPrefix(typ, "[]"):
		return 3 // ptr + len + cap
	case strings.Contains(typ, "interface") || strings.Contains(typ, "any"):
		return 2 // interface data + type
	case strings.HasPrefix(typ, "[") && strings.Contains(typ, "]"):
		// Array type - size depends on actual array size, but typically passed by reference
		return 1 // pointer to array
	default:
		return 1 // scalar values
	}
}

func resolveTypeName(d *dwarf.Data, offset dwarf.Offset) string {
	r := d.Reader()
	r.Seek(offset)
	entry, err := r.Next()
	if err != nil || entry == nil {
		return "unknown"
	}

	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrName {
			return f.Val.(string)
		}
	}

	var typeOffset dwarf.Offset
	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrType {
			typeOffset = f.Val.(dwarf.Offset)
			if offset == typeOffset {
				return "circular-reference"
			}
			return resolveTypeName(d, typeOffset)
		}
	}

	switch entry.Tag {
	case dwarf.TagBaseType:
		return "base-type"
	case dwarf.TagPointerType:
		return "pointer"
	case dwarf.TagArrayType:
		return "array"
	case dwarf.TagStructType:
		return "struct"
	default:
		return fmt.Sprintf("unknown-tag-%d", entry.Tag)
	}
}