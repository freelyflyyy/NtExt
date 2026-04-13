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
			0x48, 0x89, 0xC2,                                            // mov rdx, rax
			0x48, 0xC1, 0xEA, 0x20,                                      // shr rdx, 32
			0x48, 0x8D, 0x65, 0xE0,                                      // lea rsp, [rbp - 0x20]
			0x41, 0x5C,                                                  // pop r12
			0x5F,                                                        // pop rdi
			0x5E,                                                        // pop rsi
			0x5B,                                                        // pop rbx
			0x5D,                                                        // pop rbp
			0xC3                                                         // ret
		};

		static constexpr BYTE prepare_env[] = {
			0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, _arg[]
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, _argC 
			0x48, 0x8B, 0x0F,                                            // mov rcx, qword ptr [rdi]
			0x48, 0x83, 0xC7, 0x08,                                      // add rdi, 8
			0x48, 0xFF, 0xC8,                                            // dec rax
			0x48, 0x83, 0xF8, 0x00,                                      // cmp rax, 0
			0x74, 0x48,                                                  // je _prepare_call
			0x48, 0x8B, 0x17,                                            // mov rdx, qword ptr [rdi]
			0x48, 0x83, 0xC7, 0x08,                                      // add rdi, 8
			0x48, 0xFF, 0xC8,                                            // dec rax
			0x48, 0x83, 0xF8, 0x00,                                      // cmp rax, 0
			0x74, 0x38,                                                  // je _prepare_call
			0x4C, 0x8B, 0x07,                                            // mov r8, qword ptr [rdi]
			0x48, 0x83, 0xC7, 0x08,                                      // add rdi, 8
			0x48, 0xFF, 0xC8,                                            // dec rax
			0x48, 0x83, 0xF8, 0x00,                                      // cmp rax, 0
			0x74, 0x28,                                                  // je _prepare_call	
			0x4C, 0x8B, 0x0F,                                            // mov r9, qword ptr [rdi]
			0x48, 0x83, 0xC7, 0x08,                                      // add rdi, 8
			0x48, 0xFF, 0xC8,                                            // dec rax
			0x48, 0x83, 0xF8, 0x00,                                      // cmp rax, 0
			0x74, 0x18,                                                  // je _prepare_call
			0xA8, 0x01,                                                  // test al, 1	
			0x74, 0x04,                                                  // je _even_args
			0x48, 0x83, 0xEC, 0x08,                                      // sub rsp, 8	
			0x48, 0x8D, 0x7C, 0xC7, 0xF8,                                // lea rdi, [rdi + rax*8 - 8]	
			0xFF, 0x37,                                                  // push qword ptr [rdi]	
			0x48, 0x83, 0xEF, 0x08,                                      // sub rdi, 8	
			0x48, 0xFF, 0xC8,                                            // dec rax	
			0x75, 0xF5,                                                  // jnz _push_loop	
			0x48, 0x83, 0xEC, 0x20                                       // sub rsp, 0x20
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
