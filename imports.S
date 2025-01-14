	.set noreorder

#include "pspstub.s"

	STUB_START	"UtilsForUser",0x40010011,0x00020005
	STUB_FUNC	0x7333E539,sceKernelIcacheInvalidateAll
	STUB_FUNC	0xAF3766BB,sceKernelDcacheWritebackInvalidateAll
	STUB_END

	STUB_START	"sceRtc",0x40010011,0x00010005
	STUB_FUNC	0x9ED0AE87,sceRtcCompareTick
	STUB_END

	STUB_START	"sceVideocodec",0x90000,0x00010005
	STUB_FUNC	0xDBA273FA,sceVideocodecDecode
	STUB_END
