import sys
import subprocess

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 print_os_args.py <binary_path> [args...]")
        sys.exit(1)

    binary_path = sys.argv[1]
    binary_args = sys.argv[2:]  # Remaining arguments for the binary

    print(f"DEBUG: The arguments passed to {binary_path} are: {binary_args}")

if __name__ == "__main__":
    main()
