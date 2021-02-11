## container_monitor_bpflsm
a container monitor using eBPF LSM(for provenance) and tracepoint.  

### Installation Guide (In progress)
```bash
#for kernel build
sudo apt install build-essential libncurses5-dev bison flex libssl-dev libelf-dev bin86 kernel-package
sudo wget http://archive.ubuntu.com/ubuntu/pool/universe/d/dwarves-dfsg/dwarves_1.17-1_amd64.deb
sudo dpkg -i dwarves_1.17-1_amd64.deb
sudo wget https://www.kernel.org/pub/linux/kernel/v5.x/linux-5.8.1.tar.xz -P /usr/src

#for bpf&btf
sudo apt install clang llvm libcap-dev binutils-dev libreadline-dev gcc-multilib
# libc6-dev-i386?

#1. get a kernel source 
cd /usr/src/
sudo xz -d linux-5.8.1.tar.xz
sudo tar xvf linux-5.8.1.tar
cd linux-5.8.1

#2. kernel configuration
#su
make olddefconfig &&
  scripts/config \
  -e BPF_SYSCALL \
  -e BPF_LSM \
  -e BPF_JIT \
  -e DEBUG_INFO \
  -e DEBUG_INFO_BTF \
  -e FTRACE \
  -e DYNAMIC_FTRACE \
  -e FUNCTION_TRACER
#add 'bpf' to CONFIG_LSM string

#3. kernel build
make-kpkg clean
make-kpkg -j4 --initrd kernel_image
cd ..
#dpkg -i [linux_image_file]

#reboot
# make tools/bpf
# cp tools/bpf/bpftool/bpftool /usr/sbin
# git clone
# make
# set .so directory /etc/ld.so.conf 
```

### TODO
- Complete the installation script  
- Refactoring(Macro, functions for redundant operations,debugging options)  
- Distinguish Subject info. and Object info.  
- Add monitoring file operations  
- Add monitoring network operations
