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
)

// Function represents a parsed function with its parameters and address
type Function struct {
	Name      string     `json:"name"`
	Address   string     `json:"address"`
	Arguments []Argument `json:"arguments"`
}

// Argument represents a function parameter/argument
type Argument struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func main() {
	
	// Check for minimum required arguments
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary_path> <output_path>\n", os.Args[0])
		os.Exit(1)
	}
	
	// Get the binary path from command line
	binaryPath := os.Args[1]
	
	// Get the output path from command line (required)
	outputPath := os.Args[2]
	
	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}
	
	// Open the Go ELF binary
	f, err := elf.Open(binaryPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	
	// Load the DWARF data
	dwarfData, err := f.DWARF()
	if err != nil {
		log.Fatal(err)
	}
	
	// Create a slice to hold all functions
	functions := []Function{}
	
	// DWARF entry reader
	rdr := dwarfData.Reader()
	var currentFunc *Function
	
	// Add a safety counter to prevent potential infinite loops
	safetyCounter := 0
	maxIterations := 100000 // adjust this number based on your expected DWARF data size
	
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
			// It's a function definition
			funcName := ""
			var funcAddr uint64
			
			for _, field := range entry.Field {
				if field.Attr == dwarf.AttrName {
					funcName = field.Val.(string)
				}
				// Get the function address from the low_pc attribute
				if field.Attr == dwarf.AttrLowpc {
					// The address might be stored as a uint64 or uintptr
					switch val := field.Val.(type) {
					case uint64:
						funcAddr = val
					case uintptr:
						funcAddr = uint64(val)
					}
				}
			}
			
			// Create a new function and add it to our list if we have a name
			if funcName != "" {
				// Convert address to hexadecimal format
				hexAddr := fmt.Sprintf("0x%x", funcAddr)
				
				currentFunc = &Function{
					Name:      funcName,
					Address:   hexAddr,
					Arguments: []Argument{},
				}
				functions = append(functions, *currentFunc)
			}
			
		case dwarf.TagFormalParameter:
			// It's a function parameter/argument
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
					// Add a guard to prevent infinite recursion
					typeNameCached := fmt.Sprintf("type-offset-%d", typeOffset)
					argType = typeNameCached
					
					// Try to resolve the type name but with a recovery in case of panic
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
			
			// Update the last function in our slice with this argument
			if len(functions) > 0 {
				lastIdx := len(functions) - 1
				functions[lastIdx].Arguments = append(
					functions[lastIdx].Arguments,
					Argument{Name: argName, Type: argType},
				)
			}
		}
	}

	// Convert the data structure to JSON
	jsonData, err := json.MarshalIndent(functions, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	
	// Write JSON to file
	err = os.WriteFile(outputPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}
	
	fmt.Fprintf(os.Stderr, "Successfully wrote JSON data to %s (%d bytes)\n", 
		outputPath, len(jsonData))
	
}

// resolveTypeName follows type offsets and prints the base type name
func resolveTypeName(d *dwarf.Data, offset dwarf.Offset) string {
	r := d.Reader()
	r.Seek(offset)
	entry, err := r.Next()
	if err != nil {
		return "unknown"
	}

	if entry == nil {
		return "unknown"
	}

	// First check if there's a name attribute directly
	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrName {
			return f.Val.(string)
		}
	}

	// Then check if there's a type to follow
	var typeOffset dwarf.Offset
	hasType := false
	
	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrType {
			typeOffset = f.Val.(dwarf.Offset)
			hasType = true
			break
		}
	}

	// If we have a type reference, follow it (but with loop protection)
	if hasType {
		// Simple protection against circular references
		// by limiting recursion depth
		if offset == typeOffset {
			return "circular-reference"
		}
		return resolveTypeName(d, typeOffset)
	}

	// Fall back to tag name if we can't find a proper name
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