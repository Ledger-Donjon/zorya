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
				// After collecting all arguments, assign registers
				assignRegistersHeuristically(currentFunc)
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
				}
			}

			currentFunc.Arguments = append(currentFunc.Arguments, Argument{
				Name: argName,
				Type: argType,
			})
		}
	}

	// Catch any remaining function
	if currentFunc != nil {
		assignRegistersHeuristically(currentFunc)
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

func assignRegistersHeuristically(fn *Function) {
	regs := []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
	cur := 0
	for i := range fn.Arguments {
		n := estimateRegisterCount(fn.Arguments[i].Type)
		if cur+n > len(regs) {
			fn.Arguments[i].Registers = []string{"stack"}
			continue
		}
		fn.Arguments[i].Registers = regs[cur : cur+n]
		cur += n
	}
}

func estimateRegisterCount(typ string) int {
	typ = strings.TrimSpace(typ)
	switch {
	case typ == "string":
		return 2 // ptr + len
	case strings.HasPrefix(typ, "[]"):
		return 3 // ptr + len + cap
	case strings.Contains(typ, "interface") || strings.Contains(typ, "any"):
		return 2 // interface data + type
	default:
		return 1 // scalar
	}
}
