# QEMU-cloudimg usage

This directory can be used to do the concolic execution running a specific CPU-emulated version with QEMU in case you want to analyse your binary on a specific CPU.

In our case, we used it to analyse our binaries on a AMD Opteron 2003, to have a limited set of CPU instructions so that we don't need to implement the vectorized/optimized CPU instructions concolically.

Finally, this added overhead and was not critical in our execution, so we removed it.

We kept this directory in case we would like to handle others types of CPU in the future.

## What to modify if you want to use that functionnality ?

Go to ```/scripts/dump_memory.sh``` and you will see a whole commented section at the end of the file. This is the code to initialized the CPU registers and the memory sections inside the selected QEMU version, and you will need to work with that.

For the rest, you will need to work a bit as this functionnality is not integrated natively in the repo for now.

PS: We remove the ```external/qemu-mount``` directory because it was not usefull anymore, you will probably need to recreate it.

## Old README.md

### Dump the initial memory and CPU registers on Qemu AMD Opteron

1. **Terminal on local computer**
```
cd external/qemu-cloudimg
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
qemu-img resize jammy-server-cloudimg-amd64.img +10G

sudo qemu-system-x86_64 -cpu Opteron_G1 -m 2048 -drive file=jammy-server-cloudimg-amd64.img,format=qcow2 -drive file=cidata.iso,media=cdrom -seed 12345 -gdb tcp::1234 -net nic -net user -fsdev local,id=fsdev0,path=../qemu-mount,security_model=mapped -device virtio-9p-pci,fsdev=fsdev0,mount_tag=hostshare -nographic
```
2. **Terminal in Qemu**
The id/password for the Qemu instance are ```ubuntu/ubuntu```.
```
sudo loadkeys fr
sudo apt-get update 
sudo apt-get install gdb 9mount
sudo mkdir /mnt/host
sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
cd /mnt/host
sudo gdb [bin]
	(gdb) set disable-randomization on
	(gdb) break *0x[main.main addr]
	(gdb) set environment LD_SHOW_AUXV=1 
	(gdb) run
    	(gdb) set logging file cpu_mapping.txt
	(gdb) set logging enabled on
	(gdb) info all-registers
	(gdb) set logging enabled off
	(gdb) set logging file memory_mapping.txt
	(gdb) set logging enabled on
	(gdb) info proc mappings
	(gdb) set logging enabled off
```
3. **Terminal on local computer**
This command is supposed to create a dump_commands.txt file with commands to dump memory sections.
```
# To be done in another terminal in /zorya/external/qemu-mount
python3 parse_and_generate.py
```
4. **Terminal in Qemu**
Now, we load the second python script in gdb to be able to execute the dump commands from the file.
```
    (gdb) source execute_commands.py
    (gdb) exec dump_commands.txt 
```
