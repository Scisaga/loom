#include "textflag.h"

TEXT ·misakaTextLayoutBridgeAddress(SB),NOSPLIT,$0-8
	MOVD $misakaTextLayoutBridge<>(SB), R0
	MOVD R0, ret+0(FP)
	RET

// §7.2：仅由 syscall.SyscallN 从系统栈进入；保持非易失寄存器并尾调用 COM。
TEXT misakaTextLayoutBridge<>(SB),NOSPLIT|NOFRAME,$0
	MOVD R0, R16
	MOVD R1, R17
	MOVD 0(R17), R0
	MOVD 8(R17), R1
	MOVD 16(R17), R2
	MOVD 24(R17), R3
	FMOVS 32(R17), F0
	FMOVS 40(R17), F1
	MOVD 48(R17), R4
	B (R16)
