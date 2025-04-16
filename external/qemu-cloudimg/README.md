# QEMU-cloudimg usage

This directory can be used to do the concolic execution running a specific CPU-emulated version with QEMU in case you want to analyse your binary on a specific CPU.

In our case, we used it to analyse our binaries on a AMD Opteron 2003, to have a limited set of CPU instructions so that we don't need to implement the vectorized/optimized CPU instructions concolically.

Finally, this added overhead and was not critical in our execution, so we removed it.

We kept this directory in case we would like to handle others types of CPU in the future.

### What to modify if you want to use that functionnality ?

Go to ```/scripts/dump_memory.sh``` and you will see a whole commented section at the end of the file. This is the code to initialized the CPU registers and the memory sections inside the selected QEMU version, and you will need to work with that.

For the rest, you will need to work a bit as this functionnality is not integrated natively in the repo for now.