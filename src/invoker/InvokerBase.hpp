#pragma once
#include "../pch/stdafx.h"

namespace NtExt {

	namespace Internal {
		static constexpr BYTE backup_env[] = {
			0x55,                                                        // push rbp
			0x48, 0x89, 0xE5,                                            // mov rbp, rsp
			0x53,                                                        // push rbx
			0x56,                                                        // push rsi
			0x57,                                                        // push rdi
			0x41, 0x54,                                                  // push r12
		};
		static constexpr BYTE restore_env[] = {
			0x48, 0x8D, 0x65, 0xE0,                                      // lea rsp,[ rbp - 32 ]
			0x41, 0x5C,                                                  // pop r12
			0x5F,                                                        // pop rdi
			0x5E,                                                        // pop rsi
			0x5B,                                                        // pop rbx
			0x5D,                                                        // pop rbp
			0xC3                                                         // ret
		};

		static constexpr BYTE prepare_env[] = {
			0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rsi, _pParam
			0x49, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov r12, _argC
			0x4C, 0x89, 0xE0,                                            // mov rax, r12
			0x49, 0x83, 0xFC, 0x04,                                      // cmp r12, 4
			0x7F, 0x07,                                                  // jg +7
			0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                    // mov rax, 4
			0x48, 0xC1, 0xE0, 0x03,                                      // shl rax, 3
			0x48, 0x29, 0xC4,                                            // sub rsp, rax
			0x48, 0x83, 0xE4, 0xF0,                                      // and rsp, 0xFFFFFFF0
			0x48, 0x8B, 0x0E,                                            // mov rcx, [rsi]
			0x48, 0x8B, 0x56, 0x08,                                      // mov rdx, [rsi + 8]
			0x4C, 0x8B, 0x46, 0x10,                                      // mov r8, [rsi + 16]
			0x4C, 0x8B, 0x4E, 0x18,                                      // mov r9, [rsi + 24]
			0x49, 0x83, 0xFC, 0x04,                                      // cmp r12, 4
			0x7E, 0x17,                                                  // jle _ready
			0x49, 0xC7, 0xC3, 0x04, 0x00, 0x00, 0x00,                    // mov r11, 4
			// _loop:
			0x4A, 0x8B, 0x04, 0xDE,                                      // mov rax, [rsi + r11 * 8]
			0x4A, 0x89, 0x04, 0xDC,                                      // mov [rsp + r11 * 8], rax
			0x49, 0xFF, 0xC3,                                            // inc r11
			0x4D, 0x39, 0xE3,                                            // cmp r11, r12
			0x7C, 0xF0                                                   // jl _loop
			// _ready:
		};
	}

	class InvokerBase {
		public:
		virtual ~InvokerBase() {
			if ( _pExecuteMemory ) {
				VirtualFree(_pExecuteMemory, 0, MEM_RELEASE);
			}
		}

		InvokerBase(const InvokerBase&) = delete;
		InvokerBase& operator=(const InvokerBase&) = delete;

		protected:
		InvokerBase() : _pExecuteMemory(nullptr) {}

		LPVOID _pExecuteMemory;

		virtual VOID onBackupEnv(_Inout_ std::string* pShell) = 0;
		virtual VOID onRestoreEnv(_Inout_ std::string* pShell) = 0;
		virtual VOID onPrepareEnv(_Inout_ std::string* pShell) {}
		virtual VOID onEmitOpcode(_Inout_ std::string* pShell) {}

		_Check_return_ _Success_(return != FALSE)
			virtual BOOL CompileRoutine(_Inout_ std::string* pShell) {
			if ( !pShell ) return FALSE;
			onBackupEnv(pShell);
			onPrepareEnv(pShell);
			onEmitOpcode(pShell);
			onRestoreEnv(pShell);
			return TRUE;
		}

		public:
		_Check_return_ _Success_(return != 0)
			DWORD64 Invoke() {
			if ( !_pExecuteMemory ) {
				std::string shellcode;
				if ( !CompileRoutine(&shellcode) ) return 0;

				_pExecuteMemory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if ( !_pExecuteMemory ) return 0;

				memcpy(_pExecuteMemory, shellcode.data(), shellcode.size());
				DWORD oldProtect;
				VirtualProtect(_pExecuteMemory, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);
			}

			auto FnExecuteCode = (DWORD64(*)()) _pExecuteMemory;
			return FnExecuteCode();
		}
	};
}