# MESploit

A lightweight exploitation library for the PlayStation Portable(PSP) that allows for kernel-mode execution of user-mode functions.

This project is heavily derived from LibPspExploit, it even uses the same kernel read exploit. I created this project as a challenge for myself to find a vulnerability in the PSP kernel that would allow for a kernel-mode write exploit from user space. Im sure im not the first to discover this, but all of the research into the kernel-write exploit was done independantly (by me) using Ghidra.

## Installation
1. Make sure your PSPDEV toolchain is setup correctly
2. Clone the repository: `git clone https://github.com/maodus/mesploit.git`
3. Build the library: `cd mesploit/ && make`
4. Link against `libmesploit.a` and utilize the header `mesploit.h` in your project/homebrew

## Library Reference
- `compromiseKernel()` will modify kernel memory from user-mode and allow for privilege escalation. The library is initalized with this function so it must be called prior to anything else within the library.
- `kernelExecute(void *funcAddr)` will call the function pointed to by `funcAddr` with kernel privilege.
- `isKernelMode()` will indicate whether the current function is being executed with kernel level permissions.
- `revertKernelExploit()` will revert any changes made to kernel memory. Call this when you are done with the library.

Refer to `mesploit.h` for more detailed function explainations and view `mesploit.c` for any info on error codes.

## Acknowledgements
- Those involved with LibPspExploit (qwikrazor87, Davee, CelesteBlue, Acid_Snake)
- PSPDEV team and contributors