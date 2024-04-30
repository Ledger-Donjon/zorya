# Step 2 of the Usage of Zorya : Dump the initial memeory and CPU registers on Qemu AMD Opteron

1. **Terminal on local computer**
```
cd /external/qemu-cloudimg
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
qemu-img resize jammy-server-cloudimg-amd64.img +10G

sudo qemu-system-x86_64 -cpu Opteron_G1 -m 2048 -drive file=jammy-server-cloudimg-amd64.img,format=qcow2 -drive file=cidata.iso,media=cdrom -seed 12345 -gdb tcp::1234 -net nic -net user -fsdev local,id=fsdev0,path=../qemu-mount,security_model=mapped -device virtio-9p-pci,fsdev=fsdev0,mount_tag=hostshare -nographic
```
2. **Terminal in Qemu**
The id/password for the Qemu instance are ```ubuntu/ubuntu```.
```
sudo loadkeys fr
sudo apt-get update 
sudo install gdb 9mount
sudo mkdir /mnt/host
sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
cd /mnt/host
gdb [bin]
	(gdb) set disable-randomization on
	(gdb) break *0x[main.main addr]
	(gdb) run
    (gdb) set logging file cpu_mapping.txt
	(gdb) set logging on
	(gdb) info all-registers
	(gdb) set logging off
	(gdb) set logging file memory_mapping.txt
	(gdb) set logging on
	(gdb) info proc mappings
	(gdb) set logging off
```
3. **Terminal on local computer**
This command is supposed to create a dump_commands.txt file with commands to dump memory sections.
```
python3 parse_and_generate.py
```
4. **Terminal in Qemu**
Now, we load the second python script in gdb to be able to execute the dump commands from the file.
```
    (gdb) source execute_commands.py
    (gdb) exec dump_commands.txt 
```