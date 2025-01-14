#ifndef ME_SPLOIT_H
#define ME_SPLOIT_H

/// @brief Modifies kernel memory in a way that allows privileged execution of
/// user-mode functions
/// @return Returns 0 on success or < 0 on an error
int compromiseKernel() __attribute__((aligned(64)));

/// @brief Reverts the changes done to kernel memory, disallowing privileged
/// execution of user-mode functions
/// @return returns 1 on success or 0 on error
int revertKernelExploit();

/// @brief Execute a function with kernel level privilege
/// @param funcAddr A pointer to the function that will be executed in
/// kernel-space
/// @return Will return an integer cast of the executed function's return value
int kernelExecute(void *funcAddr);

/// @brief Checks whether or not a function is being executed from kernel-mode
/// @return Returns 1 if inside kernel-mode, 0 otherwise
int isKernelMode();

#endif