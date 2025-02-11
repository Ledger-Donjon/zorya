#!/bin/bash

BINARY="$1"
ADDR="$2"
ARG1="$3"
ARG2="$4"

if [ -z "$BINARY" ] || [ -z "$ADDR" ] || [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
    echo "Usage: $0 <binary> <0xADDRESS> <arg1> <arg2>"
    echo "Example: $0 ./getbatchfroms3-go 0x595ac0 http://example.com 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    exit 1
fi

# Log output
LOGFILE="dlv_output.log"
rm -f "$LOGFILE"

# Run Delve with non-terminal interactive mode
dlv exec "$BINARY" --allow-non-terminal-interactive=true -- "$ARG1" "$ARG2" <<EOF | tee "$LOGFILE"
break *$ADDR
continue
args
exit
EOF

echo "============================"
echo "✅ Function Argument Analysis Completed"
echo "Results saved in $LOGFILE"
echo "============================"
