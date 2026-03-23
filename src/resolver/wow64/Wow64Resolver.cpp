#include "Wow64Resolver.hpp"
#include "../../internal/NtApi.h"
#include "../../invoker/NtExtInvokers.hpp"

namespace NtExt {
	#ifdef _M_IX86
	DWORD64 NTAPI Wow64Resolver::_GetProcAddress64(_In_ DWORD64 hMod, _In_z_ const char* funcName) {
		if ( !hMod || !funcName ) return 0;
		static DWORD64 ldrGetProcedureAddress = 0;
		if ( !ldrGetProcedureAddress ) {
			ldrGetProcedureAddress = GetLdrGetProcedureAddress64();
			if ( ldrGetProcedureAddress == 0 ) return 0;
		}

		BYTE fName[ 64 ] = { 0 };
		MakeANSIStr<DWORD64>(funcName, fName);

		DWORD64 rect = 0;
		Call(ldrGetProcedureAddress)(
			(DWORD64) hMod,
			(DWORD64) &fName,
			(DWORD64) 0,
			(DWORD64) &rect
			);
		return rect;
	}

	DWORD64 Wow64Resolver::GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) {
		if ( !hMod || !funcName ) return 0;
		DWORD64 funcAddr64 = this->GetProcAddress64(hMod, funcName);
		if ( !funcAddr64 ) return 0;

		auto CheckHook = [this] (DWORD64& funcAddr) -> WORD {
			BYTE opcodes[ 8 ] = { 0 };
			memcpy64(&opcodes, funcAddr, sizeof(DWORD64));
			if ( opcodes[ 0 ] == 0x4C && opcodes[ 1 ] == 0x8B && opcodes[ 2 ] == 0xD1 && opcodes[ 3 ] == 0xB8 ) {
				return opcodes[ 5 ] << 8 | opcodes[ 4 ];
			}
			return 0;
		};

		auto _seachImpl = [CheckHook] (auto&& self, DWORD64 upAddr, DWORD64 downAddr, WORD depth = 0) -> WORD {
			if ( depth >= 500 ) return 0;
			WORD upSSN = CheckHook(upAddr);
			WORD downSSN = CheckHook(downAddr);
			if ( upSSN != 0 && downSSN != 0 ) {
				if ( downSSN - upSSN == depth * 2 ) return upSSN + depth;
			}
			return self(self, upAddr - 0x20, downAddr + 0x20, depth + 1);
		};

		WORD baseSSN = CheckHook(funcAddr64);
		if ( baseSSN != 0 ) return baseSSN;

		return _seachImpl(_seachImpl, funcAddr64 - 0x20, funcAddr64 + 0x20, 1);
	}

	DWORD64 NTAPI Wow64Resolver::GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) {
		DWORD64 teb64Addr = GetTeb64();
		if ( teb64Addr == 0 ) return 0;

		TEB64 _teb64 = { 0 };
		memcpy64(&_teb64, teb64Addr, sizeof(TEB64));
		if ( _teb64.ProcessEnvironmentBlock == 0 ) return 0;

		PEB64 _peb64 = { 0 };
		memcpy64(&_peb64, _teb64.ProcessEnvironmentBlock, sizeof(PEB64));
		if ( _peb64.Ldr == 0 ) return 0;

		PEB_LDR_DATA64 _ldr64;
		memcpy64(&_ldr64, _peb64.Ldr, sizeof(PEB_LDR_DATA64));

		DWORD64 head = _peb64.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
		DWORD64 current = _ldr64.InLoadOrderModuleList.Flink;

		while ( current != head && current != 0 ) {
			LDR_DATA_TABLE_ENTRY64 entry = { 0 };
			memcpy64(&entry, current, sizeof(LDR_DATA_TABLE_ENTRY64));

			if ( entry.BaseDllName.Buffer != 0 && entry.BaseDllName.Length > 0 ) {
				std::wstring nameBuffer(entry.BaseDllName.Length / sizeof(wchar_t), L'\0');
				memcpy64(nameBuffer.data(), entry.BaseDllName.Buffer, entry.BaseDllName.Length);

				if ( _wcsnicmp(nameBuffer.data(), moduleName, entry.BaseDllName.Length / sizeof(wchar_t)) == 0 ) {
					return current;
				}
			}
			current = entry.InLoadOrderLinks.Flink;
		}
		return 0;
	}

	DWORD64 NTAPI Wow64Resolver::GetModuleBase64(_In_z_ const wchar_t* moduleName) {
		if ( !moduleName ) return 0;
		DWORD64 ldrEntry = GetModuleLdrEntry64(moduleName);
		if ( ldrEntry == 0 ) return 0;
		LDR_DATA_TABLE_ENTRY64 entry = { 0 };
		memcpy64(&entry, ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY64));
		return entry.DllBase;
	}

	VOID NTAPI Wow64Resolver::memcpy64(_Out_writes_bytes_all_(sz) VOID* dest, _In_ DWORD64 src, _In_ SIZE_T sz) {
		if ( (nullptr == dest) || (0 == src) || (0 == sz) ) return;

		BYTE shellcode[] = {
			0xBF, 0x00, 0x00, 0x00, 0x00,                               // mov edi, dest
			0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, src
			0xB9, 0x00, 0x00, 0x00, 0x00,                               // mov ecx, sz
			0x89, 0xC8,                                                 // mov eax, ecx
			0xC1, 0xE9, 0x02,                                           // shr ecx, 2
			0xF3, 0xA5,                                                 // rep movsd
			0x89, 0xC1,                                                 // mov ecx, eax
			0x83, 0xE1, 0x03,                                           // and ecx, 3
			0xF3, 0xA4                                                  // rep movsb
		};

		*(DWORD*) (shellcode + 1) = (DWORD) dest;
		*(DWORD64*) (shellcode + 7) = src;
		*(DWORD*) (shellcode + 16) = (DWORD) sz;
		NtExt::Anycall(std::string((char*) shellcode, sizeof(shellcode)))();
	}

	VOID NTAPI Wow64Resolver::memcpy64(_In_ DWORD64 dest, _In_reads_bytes_(sz) VOID* src, _In_ SIZE_T sz) {
		if ( (0 == dest) || (nullptr == src) || (0 == sz) ) return;

		BYTE shellcode[] = {
			0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, dest
			0xBE, 0x00, 0x00, 0x00, 0x00,                               // mov esi, src
			0xB9, 0x00, 0x00, 0x00, 0x00,                               // mov ecx, sz
			0x89, 0xC8,                                                 // mov eax, ecx
			0xC1, 0xE9, 0x02,                                           // shr ecx, 2  
			0xF3, 0xA5,                                                 // rep movsd   
			0x89, 0xC1,                                                 // mov ecx, eax
			0x83, 0xE1, 0x03,                                           // and ecx, 3  
			0xF3, 0xA4                                                  // rep movsb   
		};
		*(DWORD64*) (shellcode + 2) = dest;
		*(DWORD*) (shellcode + 11) = (DWORD) src;
		*(DWORD*) (shellcode + 16) = (DWORD) sz;
		NtExt::Anycall(std::string((char*) shellcode, sizeof(shellcode)))();
	}

	DWORD64 NTAPI Wow64Resolver::GetNtdll64() {
		static DWORD64 _ntdll64 = 0;
		if ( _ntdll64 != 0 ) return _ntdll64;
		_ntdll64 = GetModuleBase64(L"ntdll.dll");
		return _ntdll64;
	}

	DWORD64 NTAPI Wow64Resolver::GetKernel64() {
		static DWORD64 _kernel64 = 0;
		if ( _kernel64 != 0 ) return _kernel64;

		DWORD64 LdrLoadDll = _GetProcAddress64(GetNtdll64(), "LdrLoadDll");
		if ( !LdrLoadDll ) return 0;

		BYTE kernel32Str[ 64 ] = { 0 };
		MakeUTFStr<DWORD64>(L"kernel32.dll", kernel32Str);

		PEB64 _peb64 = { 0 };
		memcpy64(&_peb64, GetPeb64(), sizeof(PEB64));

		HANDLE hModule = GetModuleHandle(nullptr);
		IMAGE_NT_HEADERS* pInh = (IMAGE_NT_HEADERS*) ((BYTE*) hModule + ((IMAGE_DOS_HEADER*) hModule)->e_lfanew);
		WORD& subSystem = pInh->OptionalHeader.Subsystem;

		DWORD oldProctect = 0;
		RTL_USER_PROCESS_PARAMETERS64 _upp64 = { 0 };
		memcpy64(&_upp64, _peb64.ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS64));

		if ( subSystem == IMAGE_SUBSYSTEM_WINDOWS_CUI &&
			VirtualProtect(&subSystem, sizeof(WORD), PAGE_READWRITE, &oldProctect) ) {

			RTL_USER_PROCESS_PARAMETERS64 fakeUpp = _upp64;
			fakeUpp.ConsoleHandle = 0;
			fakeUpp.ConsoleFlags = 0;
			fakeUpp.StandardInput = 0;
			fakeUpp.StandardOutput = 0;
			fakeUpp.StandardError = 0;
			fakeUpp.WindowFlags = 0;

			memcpy64(_peb64.ProcessParameters, &fakeUpp, sizeof(RTL_USER_PROCESS_PARAMETERS64));
			subSystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
		}

		Call(LdrLoadDll)(
			(DWORD64) 0,
			(DWORD64) 0,
			(DWORD64) kernel32Str,
			(DWORD64) &_kernel64
			);

		if ( oldProctect ) {
			memcpy64(_peb64.ProcessParameters, &_upp64, sizeof(RTL_USER_PROCESS_PARAMETERS64));
			subSystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
			VirtualProtect(&subSystem, sizeof(WORD), oldProctect, &oldProctect);
		}

		return _kernel64;
	}

	DWORD64 NTAPI Wow64Resolver::LoadLibrary64(_In_z_ const wchar_t* moduleName) {
		if ( !moduleName ) return 0;
		DWORD64 hMod = GetModuleBase64(moduleName);
		if ( hMod != 0 ) return hMod;

		static DWORD64 pLoadLibraryW = 0;
		if ( !pLoadLibraryW ) {
			pLoadLibraryW = _GetProcAddress64(GetKernel64(), "LoadLibraryW");
		}
		if ( !pLoadLibraryW ) return 0;

		return Call(pLoadLibraryW)((DWORD64) moduleName);
	}

	DWORD NTAPI Wow64Resolver::_GetProcAddress32(_In_ DWORD hMod, _In_z_ const char* funcName) {
		if ( !hMod || !funcName ) return 0;
		auto fnLdrGetProcedureAddress = (NTSTATUS(NTAPI*)(DWORD, DWORD, DWORD, DWORD*))(SIZE_T) GetLdrGetProcedureAddress32();
		if ( !fnLdrGetProcedureAddress ) return 0;

		BYTE fName[ 64 ] = { 0 };
		MakeANSIStr<DWORD>(funcName, fName);

		DWORD funcAddr = 0;
		NTSTATUS status = fnLdrGetProcedureAddress(hMod, (DWORD64) fName, 0, &funcAddr);
		if ( NT_SUCCESS(status) ) return funcAddr;
		return 0;
	}

	DWORD NTAPI Wow64Resolver::GetModuleBase32(_In_z_ const wchar_t* moduleName) {
		if ( !moduleName ) return 0;
		DWORD pebAddr = GetPeb32();
		if ( !pebAddr ) return 0;

		PEB32* peb32 = (PEB32*) (SIZE_T) pebAddr;
		PEB_LDR_DATA32* ldr = (PEB_LDR_DATA32*) (SIZE_T) peb32->Ldr;
		if ( !ldr ) return 0;

		DWORD listHead = (DWORD) (SIZE_T) &ldr->InLoadOrderModuleList;
		DWORD currentNode = ldr->InLoadOrderModuleList.Flink;

		while ( currentNode != listHead && currentNode != 0 ) {
			LDR_DATA_TABLE_ENTRY32* entry = (LDR_DATA_TABLE_ENTRY32*) (SIZE_T) currentNode;
			if ( entry->DllBase != 0 && entry->BaseDllName.Buffer != 0 ) {
				if ( _wcsicmp((wchar_t*) (SIZE_T) entry->BaseDllName.Buffer, moduleName) == 0 ) {
					return entry->DllBase;
				}
			}
			currentNode = entry->InLoadOrderLinks.Flink;
		}
		return 0;
	}

	DWORD NTAPI Wow64Resolver::GetTeb32() {
		DWORD _teb32 = 0;
		_teb32 = __readfsdword(FIELD_OFFSET(NT_TIB, Self));
		return _teb32;
	}

	DWORD NTAPI Wow64Resolver::GetPeb32() {
		DWORD _peb32 = 0;
		_peb32 = __readfsdword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
		return _peb32;
	}

	DWORD NTAPI Wow64Resolver::GetNtdll32() {
		static DWORD _ntdll32 = 0;
		if ( _ntdll32 != 0 ) return _ntdll32;
		_ntdll32 = GetModuleBase32(L"ntdll.dll");
		return _ntdll32;
	}

	DWORD Wow64Resolver::GetKernel32() {
		static DWORD _kernel32 = 0;
		if ( _kernel32 != 0 ) return _kernel32;
		_kernel32 = GetModuleBase32(L"kernel32.dll");
		return _kernel32;
	}

	DWORD NTAPI Wow64Resolver::GetLdrGetProcedureAddress32() {
		static DWORD _ldrGetProcAddr32 = 0;
		if ( _ldrGetProcAddr32 != 0 ) return _ldrGetProcAddr32;

		DWORD dllBase = GetNtdll32();
		if ( !dllBase ) return 0;

		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*) (SIZE_T) dllBase;
		if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) return 0;

		IMAGE_NT_HEADERS32* ntHeaders = (IMAGE_NT_HEADERS32*) (SIZE_T) (dllBase + dosHeader->e_lfanew);
		if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) return 0;

		DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
		if ( !exportRva ) return 0;

		IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*) (SIZE_T) (dllBase + exportRva);
		DWORD* nameTable = (DWORD*) (SIZE_T) (dllBase + exportDir->AddressOfNames);
		WORD* ordTable = (WORD*) (SIZE_T) (dllBase + exportDir->AddressOfNameOrdinals);
		DWORD* funcTable = (DWORD*) (SIZE_T) (dllBase + exportDir->AddressOfFunctions);

		for ( DWORD i = 0; i < exportDir->NumberOfNames; i++ ) {
			char* funcName = (char*) (SIZE_T) (dllBase + nameTable[ i ]);
			if ( strcmp(funcName, "LdrGetProcedureAddress") == 0 ) {
				_ldrGetProcAddr32 = dllBase + funcTable[ ordTable[ i ] ];
				return _ldrGetProcAddr32;
			}
		}
		return 0;
	}

	DWORD NTAPI Wow64Resolver::LoadLibrary32(_In_z_ const wchar_t* moduleName) {
		if ( !moduleName ) return 0;
		DWORD hMod = GetModuleBase32(moduleName);
		if ( hMod != 0 ) return hMod;

		static DWORD pLdrLoadDll32 = 0;
		if ( !pLdrLoadDll32 ) {
			pLdrLoadDll32 = GetProcAddress32(GetNtdll32(), "LdrLoadDll");
		}
		if ( !pLdrLoadDll32 ) return 0;

		BYTE buffer[ 64 ] = { 0 };
		MakeUTFStr < DWORD >(moduleName, buffer);

		DWORD hResult32 = 0;
		NTSTATUS status = ((NTSTATUS(NTAPI*)(DWORD, DWORD, DWORD, DWORD))(SIZE_T) pLdrLoadDll32)(NULL, NULL, (DWORD) (SIZE_T) buffer, (DWORD) (SIZE_T) &hResult32);
		if ( NT_SUCCESS(status) ) return hResult32;
		return 0;
	}

	DWORD64 NTAPI Wow64Resolver::GetLdrGetProcedureAddress64() {
		DWORD64 dllBase = GetNtdll64();
		if ( !dllBase ) return 0;

		IMAGE_DOS_HEADER idh;
		memcpy64(&idh, dllBase, sizeof(IMAGE_DOS_HEADER));

		IMAGE_NT_HEADERS64 inth;
		memcpy64(&inth, dllBase + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

		IMAGE_EXPORT_DIRECTORY ied;
		memcpy64(&ied, dllBase + inth.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));

		std::vector < DWORD > rvaTable(ied.NumberOfFunctions, 0);
		std::vector < DWORD > nameTable(ied.NumberOfNames, 0);
		std::vector < WORD > ordTable(ied.NumberOfNames, 0);

		memcpy64(rvaTable.data(), dllBase + ied.AddressOfFunctions, ied.NumberOfFunctions * sizeof(DWORD));
		memcpy64(nameTable.data(), dllBase + ied.AddressOfNames, ied.NumberOfNames * sizeof(DWORD));
		memcpy64(ordTable.data(), dllBase + ied.AddressOfNameOrdinals, ied.NumberOfNames * sizeof(WORD));

		for ( DWORD i = 0; i < ied.NumberOfNames; i++ ) {
			char funcName[ 256 ] = { 0 };
			memcpy64(funcName, dllBase + nameTable[ i ], sizeof(funcName) - 1);
			if ( strcmp(funcName, "LdrGetProcedureAddress") != 0 ) continue;
			else return dllBase + rvaTable[ ordTable[ i ] ];
		}
		return 0;
	}

	DWORD64 NTAPI Wow64Resolver::GetTeb64() {
		return Anycall(std::string("\x65\x48\x8B\x04\x25\x30\x00\x00\x00", 9))();  // mov rax, qword ptr gs:[0x30]
	}

	DWORD64 NTAPI Wow64Resolver::GetPeb64() {
		return Anycall(std::string("\x65\x48\x8B\x04\x25\x60\x00\x00\x00", 9))();  // mov rax, qword ptr gs:[0x60]
	}
	#endif
}