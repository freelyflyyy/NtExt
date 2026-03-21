#pragma once
#include "NtCallExt.h"

namespace NtExt {
	class X64NtCallExt : public NtCallExt {
		public:
		~X64NtCallExt() override = default;

		DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) override;
		DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName) override;
		DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) override;
		DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) override;
		DWORD64 NTAPI GetTeb64() override;
		DWORD64 NTAPI GetPeb64() override;
		DWORD64 NTAPI GetNtdll64() override;
		DWORD64 NTAPI GetKernel64() override;
		DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) override;

		template<typename... Args>
		NTSTATUS X64Call(const DWORD64& funcAddr, Args&&... args) {
			if ( !funcAddr ) {
				return STATUS_INVALID_ADDRESS;
			}
			auto _buildCallAction = [funcAddr] (std::string& _shellcode) {
				BYTE call_stub[] = {
					0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,//mov rax, funcAddr
					0xFF, 0xD0                                                 //call rax
				};
				*(DWORD64*) (call_stub + 2) = funcAddr;
				_shellcode.append((char*)call_stub, sizeof(call_stub));
			};
			constexpr DWORD64 _argC = sizeof...(args) > 4 ? sizeof...(args) : 4;
			const DWORD64 _argArray[ _argC ] = { (DWORD64) std::forward<Args>(args)... };
			return (NTSTATUS)_X64BuildExecute(_buildCallAction, _argArray, sizeof...(args));
		}

		template<typename... Args>
		NTSTATUS X64SysCall(const WORD& ssn, Args&&... args) {
			if ( !ssn ) {
				return STATUS_INVALID_PARAMETER;
			}

			auto _buildSysCallAction = [ssn] (std::string& _shellcode) {
				BYTE syscall_stub[] = {
					0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00,                  // lea r11, [rip + 12] 
					0x41, 0x53,                                                // push r11 
					0x49, 0x89, 0xCA,                                          // mov r10, rcx
					0xB8, 0x00, 0x00, 0x00, 0x00,                              // mov eax, ssn
					0x0F, 0x05,                                                // syscall
					0x48, 0x83, 0xC4, 0x08                                     // add rsp, 8
				};
				*(DWORD*) (syscall_stub + 13) = (DWORD) ssn;
				_shellcode.append((char*) syscall_stub, sizeof(syscall_stub));
			};

			constexpr DWORD _argC = sizeof...(Args) < 4 ? 4 : sizeof...(Args);
			const DWORD64 _argArray[ _argC ] = { (DWORD64) std::forward<Args>(args)... };

			return (NTSTATUS) _X64BuildExecute(_buildSysCallAction, _argArray, sizeof...(Args));
		}

		private:
		DWORD64 NTAPI _X64BuildExecute(std::function<void(std::string&)> _shellcode, const DWORD64* _pParam, const DWORD& _argC) override;
		DWORD64 NTAPI _X64DisptachExecute(std::string _shellcode) override;
	};
}