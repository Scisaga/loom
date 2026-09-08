#include "textflag.h"

TEXT ·misakaTextFormatBridgeAddress(SB),NOSPLIT,$0-8
	MOVD $misakaTextFormatBridge<>(SB), R0
	MOVD R0, ret+0(FP)
	RET

// §7.2：仅允许 syscall.SyscallN 从系统栈进入此 Windows ARM64 ABI 桥。
// R0 为 COM 方法，R1 指向 misakaTextFormatArgs。
// 保持 LR 与非易失寄存器不变，重排参数后尾调用目标方法。
TEXT misakaTextFormatBridge<>(SB),NOSPLIT|NOFRAME,$0
	MOVD R0, R16
	MOVD R1, R17
	MOVD 0(R17), R0
	MOVD 8(R17), R1
	MOVD 16(R17), R2
	MOVD 24(R17), R3
	MOVD 32(R17), R4
	MOVD 40(R17), R5
	FMOVS 48(R17), F0
	MOVD 56(R17), R6
	MOVD 64(R17), R7
	B (R16)
