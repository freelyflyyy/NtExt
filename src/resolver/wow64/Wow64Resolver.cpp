#include "Wow64Resolver.hpp"
#include "../../internal/NtStructs.h"
#include "../../internal/ScopeAction.hpp"
#include "../../invoker/NtExtInvokers.hpp"

namespace NtExt {
	#ifdef _M_IX86
	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetProcAddress64Impl(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) {
		if ( !ModuleBase || !FunctionName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base or function name.");
		}
		static DWORD64 ldrGetProcedureAddress = 0;
		if ( !ldrGetProcedureAddress ) {
			auto proc = GetLdrGetProcedureAddress64();
			if ( !proc ) {
				return NtResult<DWORD64>::Failure(proc);
			}
			ldrGetProcedureAddress = proc.Value();
		}

		BYTE fName[ 64 ] = { 0 };
		MakeANSIStr<DWORD64>(FunctionName, fName);

		DWORD64 rect = 0;
		auto call = Call(ldrGetProcedureAddress)(
			(DWORD64) ModuleBase,
			(DWORD64) &fName,
			(DWORD64) 0,
			(DWORD64) &rect
			);
		if ( !call ) {
			return NtResult<DWORD64>::Failure(call);
		}

		NTSTATUS status = (NTSTATUS) call.Value();
		if ( !NT_SUCCESS(status) ) {
			return NtResult<DWORD64>::Failure(status, L"LdrGetProcedureAddress failed.");
		}
		if ( !rect ) {
			return NtResult<DWORD64>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"Procedure not found.");
		}
		return NtResult<DWORD64>::Success(rect);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetSyscallNumber64(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) {
		if ( !ModuleBase || !FunctionName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base or function name.");
		}

		auto funcAddr64 = GetProcAddress64(ModuleBase, FunctionName);
		if ( !funcAddr64 ) {
			return NtResult<DWORD64>::Failure(funcAddr64);
		}
		auto _getSysPacked = [this] (DWORD64 funcAddr) -> DWORD64 {
			BYTE opcodes[ 8 ] = { 0 };
			memcpy64(&opcodes, funcAddr, sizeof(DWORD64));
			if ( opcodes[ 0 ] == 0x4C && opcodes[ 1 ] == 0x8B && opcodes[ 2 ] == 0xD1 && opcodes[ 3 ] == 0xB8 ) {
				WORD _ssn = opcodes[ 5 ] << 8 | opcodes[ 4 ];
				DWORD64 _syscallAddr = funcAddr + 0x12;
				return ((DWORD64) _ssn << 48) | _syscallAddr;
			}
			return 0;
		};

		auto _searchImpl = [&_getSysPacked] (auto&& self, DWORD64 upAddr, DWORD64 downAddr, WORD depth = 0) -> DWORD64 {
			if ( depth >= 500 ) {
				return 0;
			}
			DWORD64 _upPacked = _getSysPacked(upAddr);
			DWORD64 _downPacked = _getSysPacked(downAddr);
			if ( _upPacked != 0 && _downPacked != 0 ) {
				WORD _upSSN = (WORD) (_upPacked >> 48);
				WORD _downSSN = (WORD) (_downPacked >> 48);
				if ( _downSSN - _upSSN == depth * 2 ) {
					WORD _targetSsn = _upSSN + depth;
					DWORD64 _targetSyscallAddr = _upPacked & 0x0000FFFFFFFFFFFF;
					return ((DWORD64) _targetSsn << 48) | _targetSyscallAddr;
				}
			}
			return self(self, upAddr - 0x20, downAddr + 0x20, depth + 1);
		};

		DWORD64 basePacked = _getSysPacked(funcAddr64.Value());
		if ( basePacked ) {
			return NtResult<DWORD64>::Success(basePacked);
		}

		DWORD64 syscallContext = _searchImpl(_searchImpl, funcAddr64.Value() - 0x20, funcAddr64.Value() + 0x20, 1);
		if ( !syscallContext ) {
			return NtResult<DWORD64>::Failure(STATUS_NOT_FOUND, L"Syscall context not found.");
		}
		return NtResult<DWORD64>::Success(syscallContext);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetModuleLdrEntry64(_In_z_ PCWSTR ModuleName) {
		if ( !ModuleName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module name.");
		}
		DWORD64 teb64Addr = GetTeb64();
		if ( teb64Addr == 0 ) {
			return NtResult<DWORD64>::Failure(STATUS_UNSUCCESSFUL, L"Unable to read 64-bit TEB.");
		}

		TEB64 _teb64 = { 0 };
		memcpy64(&_teb64, teb64Addr, sizeof(TEB64));
		if ( _teb64.ProcessEnvironmentBlock == 0 ) {
			return NtResult<DWORD64>::Failure(STATUS_UNSUCCESSFUL, L"Unable to read 64-bit PEB.");
		}

		PEB64 _peb64 = { 0 };
		memcpy64(&_peb64, _teb64.ProcessEnvironmentBlock, sizeof(PEB64));
		if ( _peb64.Ldr == 0 ) {
			return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"Loader data not found.");
		}

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

				if ( _wcsnicmp(nameBuffer.data(), ModuleName, entry.BaseDllName.Length / sizeof(wchar_t)) == 0 ) {
					return NtResult<DWORD64>::Success(current);
				}
			}
			current = entry.InLoadOrderLinks.Flink;
		}
		return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"Module not found.");
	}

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetModuleBase64(_In_z_ PCWSTR ModuleName) {
		auto ldrEntry = GetModuleLdrEntry64(ModuleName);
		if ( !ldrEntry ) {
			return NtResult<DWORD64>::Failure(ldrEntry);
		}
		LDR_DATA_TABLE_ENTRY64 entry = { 0 };
		memcpy64(&entry, ldrEntry.Value(), sizeof(LDR_DATA_TABLE_ENTRY64));
		if ( !entry.DllBase ) {
			return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"Module base not found.");
		}
		return NtResult<DWORD64>::Success(entry.DllBase);
	}

	#pragma warning(push)
	#pragma warning(disable: 6101)
	VOID NTAPI Wow64Resolver::memcpy64(_Out_writes_bytes_all_(Size) PVOID Destination, _In_ DWORD64 Source, _In_ SIZE_T Size) {
		if ( (nullptr == Destination) || (0 == Source) || (0 == Size) ) {
			return;
		}

		BYTE shellcode[] = {
			0xBF, 0x00, 0x00, 0x00, 0x00,
			0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xB9, 0x00, 0x00, 0x00, 0x00,
			0xFC,
			0x89, 0xC8,
			0xC1, 0xE9, 0x02,
			0xF3, 0xA5,
			0x89, 0xC1,
			0x83, 0xE1, 0x03,
			0xF3, 0xA4
		};

		*(DWORD*) (shellcode + 1) = (DWORD) Destination;
		*(DWORD64*) (shellcode + 7) = Source;
		*(DWORD*) (shellcode + 16) = (DWORD) Size;

		(void) NtExt::Anycall(std::string((char*) shellcode, sizeof(shellcode)))();
	}
	#pragma warning(pop)

	#pragma warning(push)
	#pragma warning(disable: 6101)
	VOID NTAPI Wow64Resolver::memcpy64(_In_ DWORD64 Destination, _In_reads_bytes_(Size) PVOID Source, _In_ SIZE_T Size) {
		if ( (0 == Destination) || (nullptr == Source) || (0 == Size) ) {
			return;
		}

		BYTE shellcode[] = {
			0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xBE, 0x00, 0x00, 0x00, 0x00,
			0xB9, 0x00, 0x00, 0x00, 0x00,
			0xFC,
			0x89, 0xC8,
			0xC1, 0xE9, 0x02,
			0xF3, 0xA5,
			0x89, 0xC1,
			0x83, 0xE1, 0x03,
			0xF3, 0xA4
		};
		*(DWORD64*) (shellcode + 2) = Destination;
		*(DWORD*) (shellcode + 11) = (DWORD) Source;
		*(DWORD*) (shellcode + 16) = (DWORD) Size;

		(void) NtExt::Anycall(std::string((char*) shellcode, sizeof(shellcode)))();
	}
	#pragma warning(pop)

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetNtdll64() {
		static DWORD64 _ntdll64 = 0;
		if ( _ntdll64 != 0 ) {
			return NtResult<DWORD64>::Success(_ntdll64);
		}
		auto moduleBase = GetModuleBase64(L"ntdll.dll");
		if ( !moduleBase ) {
			return NtResult<DWORD64>::Failure(moduleBase);
		}
		_ntdll64 = moduleBase.Value();
		return NtResult<DWORD64>::Success(_ntdll64);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetKernel64() {
		static DWORD64 _kernel64 = 0;
		if ( _kernel64 != 0 ) {
			return NtResult<DWORD64>::Success(_kernel64);
		}

		auto ntdll64 = GetNtdll64();
		if ( !ntdll64 ) {
			return NtResult<DWORD64>::Failure(ntdll64);
		}
		auto ldrLoadDll = GetProcAddress64(ntdll64.Value(), "LdrLoadDll");
		if ( !ldrLoadDll ) {
			return NtResult<DWORD64>::Failure(ldrLoadDll);
		}
		BYTE kernel32Str[ 64 ] = { 0 };
		MakeUTFStr<DWORD64>(L"kernel32.dll", kernel32Str);

		PEB64 _peb64 = { 0 };
		DWORD64 peb64 = GetPeb64();
		if ( !peb64 ) {
			return NtResult<DWORD64>::Failure(STATUS_UNSUCCESSFUL, L"Unable to read 64-bit PEB.");
		}
		memcpy64(&_peb64, peb64, sizeof(PEB64));

		HANDLE hModule = GetModuleHandle(nullptr);
		auto* pInh = (IMAGE_NT_HEADERS*) ((BYTE*) hModule + ((IMAGE_DOS_HEADER*) hModule)->e_lfanew);
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

			NTEXT_DEFER {
				memcpy64(_peb64.ProcessParameters, &_upp64, sizeof(RTL_USER_PROCESS_PARAMETERS64));
				subSystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
				VirtualProtect(&subSystem, sizeof(WORD), oldProctect, &oldProctect);
			};
		}

		auto loadDll = Call(ldrLoadDll.Value())(
			(DWORD64) 0,
			(DWORD64) 0,
			(DWORD64) kernel32Str,
			(DWORD64) &_kernel64
			);

		if ( !loadDll ) {
			return NtResult<DWORD64>::Failure(loadDll);
		}
		NTSTATUS status = (NTSTATUS) loadDll.Value();
		if ( !NT_SUCCESS(status) ) {
			return NtResult<DWORD64>::Failure(status, L"LdrLoadDll failed.");
		}
		if ( !_kernel64 ) {
			return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"kernel32.dll was not loaded.");
		}
		return NtResult<DWORD64>::Success(_kernel64);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::LoadLibrary64(_In_z_ PCWSTR ModuleName) {
		if ( !ModuleName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module name.");
		}
		auto moduleBase = GetModuleBase64(ModuleName);
		if ( moduleBase ) {
			return moduleBase;
		}
		if ( moduleBase.Code() != STATUS_DLL_NOT_FOUND ) {
			return NtResult<DWORD64>::Failure(moduleBase);
		}

		auto kernel64 = GetKernel64();
		if ( !kernel64 ) {
			return NtResult<DWORD64>::Failure(kernel64);
		}
		auto loadLibrary = GetProcAddress64(kernel64.Value(), "LoadLibraryW");
		if ( !loadLibrary ) {
			return NtResult<DWORD64>::Failure(loadLibrary);
		}
		auto loadModule = Call(loadLibrary.Value())((DWORD64) ModuleName);
		if ( !loadModule ) {
			return NtResult<DWORD64>::Failure(loadModule);
		}
		if ( !loadModule.Value() ) {
			return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"LoadLibraryW returned an empty module base.");
		}
		return loadModule;
	}

	_Check_return_
		NtStatus NTAPI Wow64Resolver::MapKnownDllSection64(_In_z_ PCWSTR DllName, _Out_ DWORD64* MappedBase, _Out_opt_ DWORD64* ViewSize) {
		if ( !MappedBase ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid mapped base output.");
		}
		*MappedBase = 0;
		if ( !DllName ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid DLL name.");
		}
		if ( ViewSize ) {
			*ViewSize = 0;
		}

		WCHAR knownDllPath[ MAX_PATH ] = L"\\KnownDlls\\";
		SIZE_T pathOffset = 11;

		for ( SIZE_T i = 0; DllName[ i ] != L'\0'; ++i ) {
			if ( pathOffset + 1 >= MAX_PATH ) {
				return NtStatus::Failure(STATUS_NAME_TOO_LONG, L"KnownDll path is too long.");
			}
			knownDllPath[ pathOffset++ ] = DllName[ i ];
		}
		knownDllPath[ pathOffset ] = L'\0';

		auto ntdllBase = GetNtdll64();
		if ( !ntdllBase ) {
			return NtStatus::Failure(ntdllBase);
		}
		auto ntOpenSection = GetSyscallNumber64(ntdllBase.Value(), "NtOpenSection");
		if ( !ntOpenSection ) {
			return NtStatus::Failure(ntOpenSection);
		}
		auto ntMapViewOfSection = GetSyscallNumber64(ntdllBase.Value(), "NtMapViewOfSection");
		if ( !ntMapViewOfSection ) {
			return NtStatus::Failure(ntMapViewOfSection);
		}
		auto ntClose = GetSyscallNumber64(ntdllBase.Value(), "NtClose");
		if ( !ntClose ) {
			return NtStatus::Failure(ntClose);
		}

		BYTE sectionName[ 64 ] = { 0 };
		MakeUTFStr<DWORD64>(knownDllPath, sectionName);

		OBJECT_ATTRIBUTES64 ObjectAttributes = { 0 };
		InitializeObjectAttributesEx64(
			&ObjectAttributes,
			&sectionName,
			OBJ_CASE_INSENSITIVE,
			0,
			0
		);

		DWORD64 hSection = 0;
		DWORD64 mappedBase = 0;
		DWORD64 viewSize = 0;

		auto openSection = Syscall(ntOpenSection.Value())(
			(DWORD64) &hSection,
			SECTION_MAP_READ,
			(DWORD64) &ObjectAttributes
		);
		if ( !openSection ) {
			return NtStatus::Failure(openSection);
		}
		if ( !hSection ) {
			return NtStatus::Failure(STATUS_INVALID_HANDLE, L"NtOpenSection returned an empty handle.");
		}

		NTEXT_DEFER {
			(VOID) Syscall(ntClose.Value())(hSection);
		};

		auto mapView = Syscall(ntMapViewOfSection.Value())(
			hSection,
			(DWORD64) GetCurrentProcess(),
			(DWORD64) &mappedBase,
			0, 0, 0,
			(DWORD64) &viewSize,
			ViewUnmap,
			0,
			PAGE_READONLY
		);
		if ( !mapView ) {
			return NtStatus::Failure(mapView);
		}
		if ( !mappedBase ) {
			return NtStatus::Failure(STATUS_UNSUCCESSFUL, L"NtMapViewOfSection returned an empty base.");
		}

		*MappedBase = mappedBase;
		if ( ViewSize ) {
			*ViewSize = viewSize;
		}
		return NtStatus::Success();
	}

	_Check_return_
		NtStatus NTAPI Wow64Resolver::UnmapKnownDllSection64(_In_ DWORD64 MappedBase) {
		if ( !MappedBase ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid mapped base.");
		}
		auto ntdllBase = GetNtdll64();
		if ( !ntdllBase ) {
			return NtStatus::Failure(ntdllBase);
		}
		auto ntUnmapViewOfSection = GetSyscallNumber64(ntdllBase.Value(), "NtUnmapViewOfSection");
		if ( !ntUnmapViewOfSection ) {
			return NtStatus::Failure(ntUnmapViewOfSection);
		}
		return Syscall(ntUnmapViewOfSection.Value())(
			(DWORD64) -1,
			MappedBase
			);
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::GetProcAddress32Impl(_In_ DWORD ModuleBase, _In_z_ PCSTR FunctionName) {
		if ( !ModuleBase || !FunctionName ) {
			return NtResult<DWORD>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base or function name.");
		}

		auto ldrGetProcedureAddress = GetLdrGetProcedureAddress32();
		if ( !ldrGetProcedureAddress ) {
			return NtResult<DWORD>::Failure(ldrGetProcedureAddress);
		}
		auto fnLdrGetProcedureAddress = (NTSTATUS(NTAPI*)(DWORD, DWORD, DWORD, DWORD*))(SIZE_T) ldrGetProcedureAddress.Value();

		BYTE fName[ 64 ] = { 0 };
		MakeANSIStr<DWORD>(FunctionName, fName);

		DWORD funcAddr = 0;
		NTSTATUS status = fnLdrGetProcedureAddress(ModuleBase, (DWORD64) fName, 0, &funcAddr);
		if ( !NT_SUCCESS(status) ) {
			return NtResult<DWORD>::Failure(status, L"LdrGetProcedureAddress failed.");
		}
		if ( !funcAddr ) {
			return NtResult<DWORD>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"Procedure not found.");
		}
		return NtResult<DWORD>::Success(funcAddr);
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::GetModuleLdrEntry32(_In_z_ PCWSTR ModuleName) {
		if ( !ModuleName ) {
			return NtResult<DWORD>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module name.");
		}

		DWORD pebAddr = GetPeb32();
		if ( !pebAddr ) {
			return NtResult<DWORD>::Failure(STATUS_UNSUCCESSFUL, L"Unable to read 32-bit PEB.");
		}

		auto* peb32 = (PEB32*) pebAddr;
		auto ldr = (PEB_LDR_DATA32*) peb32->Ldr;
		if ( !ldr ) {
			return NtResult<DWORD>::Failure(STATUS_DLL_NOT_FOUND, L"Loader data not found.");
		}

		DWORD listHead = peb32->Ldr + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList);
		DWORD currentNode = ldr->InLoadOrderModuleList.Flink;

		for ( DWORD visitedCount = 0; currentNode != 0 && currentNode != listHead; ++visitedCount ) {
			if ( visitedCount >= 512 ) {
				return NtResult<DWORD>::Failure(STATUS_UNSUCCESSFUL, L"Invalid 32-bit loader module list.");
			}

			auto* entry = (LDR_DATA_TABLE_ENTRY32*) currentNode;
			if ( entry->DllBase != 0 && entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length != 0 ) {
				SIZE_T entryNameLength = entry->BaseDllName.Length / sizeof(WCHAR);
				if ( _wcsnicmp((PCWSTR) (SIZE_T) entry->BaseDllName.Buffer, ModuleName, entryNameLength) == 0 ) {
					return NtResult<DWORD>::Success(currentNode);
				}
			}

			if ( currentNode == entry->InLoadOrderLinks.Flink ) {
				return NtResult<DWORD>::Failure(STATUS_UNSUCCESSFUL, L"Invalid 32-bit loader module list.");
			}

			currentNode = entry->InLoadOrderLinks.Flink;
		}
		return NtResult<DWORD>::Failure(STATUS_DLL_NOT_FOUND, L"Module not found.");
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::GetModuleBase32(_In_z_ PCWSTR ModuleName) {
		auto ldrEntry = GetModuleLdrEntry32(ModuleName);
		if ( !ldrEntry ) {
			return NtResult<DWORD>::Failure(ldrEntry);
		}

		auto* entry = (LDR_DATA_TABLE_ENTRY32*) (SIZE_T) ldrEntry.Value();
		if ( !entry->DllBase ) {
			return NtResult<DWORD>::Failure(STATUS_DLL_NOT_FOUND, L"Module base not found.");
		}
		return NtResult<DWORD>::Success(entry->DllBase);
	}

	_Check_return_ _Success_(return != 0)
		DWORD NTAPI Wow64Resolver::GetTeb32() {
		return __readfsdword(FIELD_OFFSET(NT_TIB, Self));
	}

	_Check_return_ _Success_(return != 0)
		DWORD NTAPI Wow64Resolver::GetPeb32() {
		return __readfsdword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::GetNtdll32() {
		static DWORD _ntdll32 = 0;
		if ( _ntdll32 != 0 ) {
			return NtResult<DWORD>::Success(_ntdll32);
		}
		auto moduleBase = GetModuleBase32(L"ntdll.dll");
		if ( !moduleBase ) {
			return NtResult<DWORD>::Failure(moduleBase);
		}
		_ntdll32 = moduleBase.Value();
		return NtResult<DWORD>::Success(_ntdll32);
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::GetKernel32() {
		static DWORD _kernel32 = 0;
		if ( _kernel32 != 0 ) {
			return NtResult<DWORD>::Success(_kernel32);
		}
		auto moduleBase = GetModuleBase32(L"kernel32.dll");
		if ( !moduleBase ) {
			return NtResult<DWORD>::Failure(moduleBase);
		}
		_kernel32 = moduleBase.Value();
		return NtResult<DWORD>::Success(_kernel32);
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::GetLdrGetProcedureAddress32() {
		static DWORD _ldrGetProcAddr32 = 0;
		if ( _ldrGetProcAddr32 != 0 ) {
			return NtResult<DWORD>::Success(_ldrGetProcAddr32);
		}

		auto dllBase = GetNtdll32();
		if ( !dllBase ) {
			return NtResult<DWORD>::Failure(dllBase);
		}
		auto* dosHeader = (IMAGE_DOS_HEADER*) (SIZE_T) dllBase.Value();
		if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
			return NtResult<DWORD>::Failure(STATUS_INVALID_IMAGE_FORMAT, L"Invalid DOS signature.");
		}

		auto ntHeaders = (IMAGE_NT_HEADERS32*) (SIZE_T) (dllBase.Value() + dosHeader->e_lfanew);
		if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) {
			return NtResult<DWORD>::Failure(STATUS_INVALID_IMAGE_FORMAT, L"Invalid NT signature.");
		}

		DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
		if ( !exportRva ) {
			return NtResult<DWORD>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"Export directory not found.");
		}

		auto exportDir = (IMAGE_EXPORT_DIRECTORY*) (SIZE_T) (dllBase.Value() + exportRva);
		auto nameTable = (DWORD*) (SIZE_T) (dllBase.Value() + exportDir->AddressOfNames);
		WORD* ordTable = (WORD*) (SIZE_T) (dllBase.Value() + exportDir->AddressOfNameOrdinals);
		auto funcTable = (DWORD*) (SIZE_T) (dllBase.Value() + exportDir->AddressOfFunctions);

		for ( DWORD i = 0; i < exportDir->NumberOfNames; i++ ) {
			char* funcName = (char*) (SIZE_T) (dllBase.Value() + nameTable[ i ]);
			if ( strcmp(funcName, "LdrGetProcedureAddress") == 0 ) {
				DWORD functionRva = funcTable[ ordTable[ i ] ];
				if ( !functionRva ) {
					return NtResult<DWORD>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"LdrGetProcedureAddress has an empty RVA.");
				}
				_ldrGetProcAddr32 = dllBase.Value() + functionRva;
				return NtResult<DWORD>::Success(_ldrGetProcAddr32);
			}
		}
		return NtResult<DWORD>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"LdrGetProcedureAddress not found.");
	}

	_Check_return_
		NtResult<DWORD> NTAPI Wow64Resolver::LoadLibrary32(_In_z_ PCWSTR ModuleName) {
		if ( !ModuleName ) {
			return NtResult<DWORD>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module name.");
		}
		auto moduleBase = GetModuleBase32(ModuleName);
		if ( moduleBase ) {
			return moduleBase;
		}
		if ( moduleBase.Code() != STATUS_DLL_NOT_FOUND ) {
			return NtResult<DWORD>::Failure(moduleBase);
		}

		auto ldrLoadDll32 = GetProcAddress32("LdrLoadDll");
		if ( !ldrLoadDll32 ) {
			return NtResult<DWORD>::Failure(ldrLoadDll32);
		}
		BYTE buffer[ 64 ] = { 0 };
		MakeUTFStr <DWORD>(ModuleName, buffer);

		DWORD loadedModule32 = 0;
		NTSTATUS status = ((NTSTATUS(NTAPI*)(DWORD, DWORD, DWORD, DWORD))(SIZE_T) ldrLoadDll32.Value())(0, 0, (DWORD) (SIZE_T) buffer, (DWORD) (SIZE_T) &loadedModule32);
		if ( !NT_SUCCESS(status) ) {
			return NtResult<DWORD>::Failure(status, L"LdrLoadDll failed.");
		}
		if ( !loadedModule32 ) {
			return NtResult<DWORD>::Failure(STATUS_UNSUCCESSFUL, L"LdrLoadDll returned an empty module base.");
		}
		return NtResult<DWORD>::Success(loadedModule32);
	}

	_Check_return_
		NtStatus NTAPI Wow64Resolver::MapKnownDllSection32(_In_z_ PCWSTR DllName, _Out_ DWORD* MappedBase, _Out_opt_ PSIZE_T ViewSize) {
		if ( !MappedBase ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid mapped base output.");
		}
		*MappedBase = 0;
		if ( !DllName ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid DLL name.");
		}
		if ( ViewSize ) {
			*ViewSize = 0;
		}

		WCHAR knownDllPath[ MAX_PATH ] = L"\\KnownDlls\\";
		SIZE_T pathOffset = 11;

		for ( SIZE_T i = 0; DllName[ i ] != L'\0'; ++i ) {
			if ( pathOffset + 1 >= MAX_PATH ) {
				return NtStatus::Failure(STATUS_NAME_TOO_LONG, L"KnownDll path is too long.");
			}
			knownDllPath[ pathOffset++ ] = DllName[ i ];
		}
		knownDllPath[ pathOffset ] = L'\0';

		auto ntdllBase = GetNtdll32();
		if ( !ntdllBase ) {
			return NtStatus::Failure(ntdllBase);
		}

		auto ntOpenSection = GetProcAddress32(ntdllBase.Value(), "NtOpenSection");
		if ( ntOpenSection.Failed() ) {
			return NtStatus::Failure(ntOpenSection);
		}
		auto ntMapViewOfSection = GetProcAddress32(ntdllBase.Value(), "NtMapViewOfSection");
		if ( ntMapViewOfSection.Failed() ) {
			return NtStatus::Failure(ntMapViewOfSection);
		}
		auto ntClose = GetProcAddress32(ntdllBase.Value(), "NtClose");
		if ( ntClose.Failed() ) {
			return NtStatus::Failure(ntClose);
		}

		BYTE sectionName[ 64 ] = { 0 };
		MakeUTFStr<DWORD>(knownDllPath, sectionName);

		OBJECT_ATTRIBUTES32 ObjectAttributes = { 0 };
		InitializeObjectAttributesEx32(
			&ObjectAttributes,
			&sectionName,
			OBJ_CASE_INSENSITIVE,
			0,
			0
		);

		DWORD hSection = 0;
		DWORD mappedBase = 0;
		SIZE_T viewSize = 0;

		auto openSection = ((NTSTATUS(NTAPI*)(DWORD*, ACCESS_MASK, DWORD))ntOpenSection.Value())(
			&hSection,
			SECTION_MAP_READ,
			(DWORD) (SIZE_T) &ObjectAttributes
			);

		if ( !NT_SUCCESS(openSection) ) {
			return NtStatus::Failure(openSection, L"NtOpenSection failed.");
		}
		if ( !hSection ) {
			return NtStatus::Failure(STATUS_INVALID_HANDLE, L"NtOpenSection returned an empty handle.");
		}

		NTEXT_DEFER{
			((NTSTATUS(NTAPI*)(DWORD))ntClose.Value())(hSection);
		};

		auto mapView = ((NTSTATUS(NTAPI*)(
						DWORD, DWORD, DWORD*, ULONG_PTR,
						SIZE_T, PLARGE_INTEGER, PSIZE_T,
						SECTION_INHERIT, ULONG, ULONG)) ntMapViewOfSection.Value())(
			hSection,
			(DWORD) -1, &mappedBase,
			0, 0, 0,
			&viewSize,
			ViewUnmap, 0,
			PAGE_READONLY
			);

		if ( !NT_SUCCESS(mapView) ) {
			return NtStatus::Failure(mapView, L"NtMapViewOfSection failed.");
		}
		if ( !mappedBase ) {
			return NtStatus::Failure(STATUS_UNSUCCESSFUL, L"NtMapViewOfSection returned an empty base.");
		}

		*MappedBase = mappedBase;
		if ( ViewSize ) {
			*ViewSize = viewSize;
		}

		return NtStatus::Success();
	}

	_Check_return_
		NtStatus NTAPI Wow64Resolver::UnmapKnownDllSection32(_In_opt_ DWORD MappedBase) {
		if ( !MappedBase ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid mapped base.");
		}

		auto ntdllBase = GetNtdll32();
		if ( !ntdllBase ) {
			return NtStatus::Failure(ntdllBase);
		}

		auto ntUnmapViewOfSection = GetProcAddress32(ntdllBase.Value(), "NtUnmapViewOfSection");
		if ( ntUnmapViewOfSection.Failed() ) {
			return NtStatus::Failure(ntUnmapViewOfSection.Code(), ntUnmapViewOfSection.Message());
		}

		NTSTATUS status = ((NTSTATUS(NTAPI*)(DWORD, DWORD)) ntUnmapViewOfSection.Value())(
			(DWORD) -1,
			MappedBase
			);

		if ( !NT_SUCCESS(status) ) {
			return NtStatus::Failure(status, L"NtUnmapViewOfSection failed.");
		}

		return NtStatus::Success();
	}

	_Check_return_
		NtResult<DWORD64> NTAPI Wow64Resolver::GetLdrGetProcedureAddress64() {
		auto dllBase = GetNtdll64();
		if ( !dllBase ) {
			return NtResult<DWORD64>::Failure(dllBase);
		}
		IMAGE_DOS_HEADER idh;
		memcpy64(&idh, dllBase.Value(), sizeof(IMAGE_DOS_HEADER));

		IMAGE_NT_HEADERS64 inth;
		memcpy64(&inth, dllBase.Value() + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

		IMAGE_EXPORT_DIRECTORY ied;
		memcpy64(&ied, dllBase.Value() + inth.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));

		std::vector < DWORD > rvaTable(ied.NumberOfFunctions, 0);
		std::vector < DWORD > nameTable(ied.NumberOfNames, 0);
		std::vector < WORD > ordTable(ied.NumberOfNames, 0);

		memcpy64(rvaTable.data(), dllBase.Value() + ied.AddressOfFunctions, ied.NumberOfFunctions * sizeof(DWORD));
		memcpy64(nameTable.data(), dllBase.Value() + ied.AddressOfNames, ied.NumberOfNames * sizeof(DWORD));
		memcpy64(ordTable.data(), dllBase.Value() + ied.AddressOfNameOrdinals, ied.NumberOfNames * sizeof(WORD));

		for ( DWORD i = 0; i < ied.NumberOfNames; i++ ) {
			char funcName[ 256 ] = { 0 };
			memcpy64(funcName, dllBase.Value() + nameTable[ i ], sizeof(funcName) - 1);
			if ( strcmp(funcName, "LdrGetProcedureAddress") == 0 ) {
				DWORD functionRva = rvaTable[ ordTable[ i ] ];
				if ( !functionRva ) {
					return NtResult<DWORD64>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"LdrGetProcedureAddress has an empty RVA.");
				}
				return NtResult<DWORD64>::Success(dllBase.Value() + functionRva);
			}
		}
		return NtResult<DWORD64>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"LdrGetProcedureAddress not found.");
	}

	_Check_return_ _Success_(return != 0)
		DWORD64 NTAPI Wow64Resolver::GetTeb64() {
		return Anycall(std::string("\x65\x48\x8B\x04\x25\x30\x00\x00\x00", 9))().ValueOr(0);
	}

	_Check_return_ _Success_(return != 0)
		DWORD64 NTAPI Wow64Resolver::GetPeb64() {
		return Anycall(std::string("\x65\x48\x8B\x04\x25\x60\x00\x00\x00", 9))().ValueOr(0);
	}
	#endif
}
