#pragma once
#include "../pch/stdafx.h"

namespace NtExt {
	#define EMIT(a) __asm __emit (a)

	// Switch to 64 bit mode
	#define x64_start \
		EMIT(0x6A) EMIT(0x33)                         /* push 0x33             */ \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)    /* call $+5              */ \
		EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05)   /* add dword [esp], 5    */ \
		EMIT(0xCB)                                    /* retf                  */

	// back to 32 bit mode
	#define x64_end \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                     /* call $+5              */  \
		EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(0x04) EMIT(0x23) EMIT(0) EMIT(0) EMIT(0) /* mov dword [rsp+4], 0x23*/ \
		EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x0D)                                    /* add dword [rsp], 0x0D */  \
		EMIT(0xCB)                                                                     /* retf                  */

	#define rex_w EMIT(0x48) __asm

	#define rax  0
	#define rcx  1
	#define rdx  2
	#define rbx  3
	#define rsp  4
	#define rbp  5
	#define rsi  6
	#define rdi  7
	#define r8   8
	#define r9   9
	#define r10  10
	#define r11  11
	#define r12  12
	#define r13  13
	#define r14  14
	#define r15  15

	// push 64 register
	#define x64_push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))

	// pop 64 register
	#define x64_pop(r)  EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

	union Reg64 {
		DWORD64 v;
		DWORD dw[ 2 ];
	};
}