#include "NtCallExt.h"
#pragma warning(push)
#pragma warning(disable: 4251)

namespace MemX {
    VOID NTAPI NtCallExt::MakeUTFStrVa(LPCWSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize) {
        if ( !lpString || !outBuffer ) return;
        SIZE_T len = wcslen(lpString);

        *(USHORT*) (outBuffer) = (USHORT) len * sizeof(WCHAR);              // Length
        *(USHORT*) (outBuffer + 2) = (USHORT) (len + 1) * sizeof(WCHAR);    // MaxLength
        WCHAR* outStr;
        if ( pointerSize == 8 ) {
            outStr = (WCHAR*) (outBuffer + 16);
            *(DWORD64*) (outBuffer + 8) = (DWORD64) outStr;                 // Buffer
        } else if ( pointerSize == 4 ) {
            outStr = (WCHAR*) (outBuffer + 8);
            *(DWORD*) (outBuffer + 4) = (DWORD) (SIZE_T) outStr;            // Buffer 
        } else {
            return;
        }
        for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = lpString[ i ];
        outStr[ len ] = L'\0';
    }

    VOID NtCallExt::MakeANSIStrVa(LPCSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize) {
        if ( !lpString || !outBuffer ) return;
        SIZE_T len = strlen(lpString);

        *(USHORT*) (outBuffer) = (USHORT) len;                    // Length
        *(USHORT*) (outBuffer + 2) = (USHORT) (len + 1);          // MaxLength

        char* outStr;
        if ( pointerSize == 8 ) {
            outStr = (char*) (outBuffer + 16);
            *(DWORD64*) (outBuffer + 8) = (DWORD64) outStr;       // Buffer
        } else if ( pointerSize == 4 ) {
            outStr = (char*) (outBuffer + 8);
            *(DWORD*) (outBuffer + 4) = (DWORD) (SIZE_T) outStr;  // Buffer 
        } else {
            return;
        }

        for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = lpString[ i ];
        outStr[ len ] = '\0';
    }

    DWORD64 NTAPI X64NtCallExt::GetProcAddress64(DWORD64 hMod, const char* funcName) {
        if ( !hMod || !funcName ) {
            return 0;
        }
        return (DWORD64) GetProcAddress((HMODULE) hMod, funcName);
    }

    DWORD64 NTAPI X64NtCallExt::GetModuleLdrEntry64(const wchar_t* moduleName) {
        if ( !moduleName ) return 0;
        PEB64* _peb64 = (PEB64*) GetPeb64();
        if ( !_peb64->Ldr ) {
            return 0;
        }
        PEB_LDR_DATA64* _ldr64 = (PEB_LDR_DATA64*) _peb64->Ldr;
        DWORD64 head = _peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
        DWORD64 current = _ldr64->InLoadOrderModuleList.Flink;
        while ( head != current && current != 0 ) {
            LDR_DATA_TABLE_ENTRY64* entry = (LDR_DATA_TABLE_ENTRY64*) current;
            if ( entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0 ) {
                if ( !_wcsnicmp((WCHAR*) entry->BaseDllName.Buffer, moduleName, entry->BaseDllName.Length / sizeof(WCHAR)) ) {
                    return current;
                }
            }
            current = entry->InLoadOrderLinks.Flink;
        }
        return 0;
    }

    DWORD64 NTAPI X64NtCallExt::GetModuleBase64(const wchar_t* moduleName) {
        if ( !moduleName ) {
            return 0;
        }
        LDR_DATA_TABLE_ENTRY64* entry = (LDR_DATA_TABLE_ENTRY64*) GetModuleLdrEntry64(moduleName);
        return entry->DllBase;
    }

    DWORD64 NTAPI X64NtCallExt::GetNtdll64() {
        static DWORD64 _ntdll64 = 0;
        if ( _ntdll64 != 0 ) {
            return _ntdll64;
        }
        _ntdll64 = (DWORD64) GetModuleBase64(L"ntdll.dll");
        return _ntdll64;
    }

    DWORD64 NTAPI X64NtCallExt::GetKernel64() {
        static DWORD64 _kernel64 = 0;
        if ( _kernel64 != 0 ) {
            return _kernel64;
        }
        _kernel64 = (DWORD64) GetModuleBase64(L"kernel32.dll");
        return _kernel64;
    }

    DWORD64 NTAPI X64NtCallExt::LoadLibrary64(const wchar_t* moduleName) {
        if ( !moduleName ) return 0;

        DWORD64 hMod = GetModuleBase64(moduleName);
        if ( hMod != 0 ) return hMod;

        static DWORD64 pLdrLoadDll = 0;
        if ( !pLdrLoadDll ) {
            pLdrLoadDll = GetProcAddress64(GetNtdll64(), "LdrLoadDll");
        }
        if ( !pLdrLoadDll ) return 0;

        BYTE buffer[ 64 ] = { 0 };
        MakeUTFStr < DWORD64 >(moduleName, buffer);

        DWORD64 hResult = { 0 };
        NTSTATUS status = X64Call(pLdrLoadDll, (DWORD64) 0, (DWORD64) 0, (DWORD64) buffer, (DWORD64) &hResult);

        if ( NT_SUCCESS(status) ) {
            return hResult;
        }

        return status;
    }

    DWORD64 NTAPI X64NtCallExt::GetTeb64() {
        Reg64 _teb64 = { 0 };
        #ifdef _WIN64
        _teb64.v = __readgsqword(FIELD_OFFSET(NT_TIB, Self));
        #endif
        return _teb64.v;
    }

    DWORD64 NTAPI X64NtCallExt::GetPeb64() {
        Reg64 _peb64 = { 0 };
        #ifdef _WIN64
        _peb64.v = __readgsqword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
        #endif
        return _peb64.v;
    }

    DWORD64 NTAPI Wow64NtCallExt::GetProcAddress64(DWORD64 hMod,
                                                   const char* funcName) {
        static DWORD64 ldrGetProcedureAddress = 0;
        if ( !ldrGetProcedureAddress ) {
            ldrGetProcedureAddress = GetLdrGetProcedureAddress();

            if ( ldrGetProcedureAddress == 0 ) return 0;
        }

        BYTE fName[ 64 ] = { 0 };
        MakeANSIStr<DWORD64>(funcName, fName);

        DWORD64 rect = 0;
        X64CallVa(ldrGetProcedureAddress, 4, (DWORD64) hMod, (DWORD64) &fName, (DWORD64) 0, (DWORD64) &rect);
        return rect;
    }

    DWORD64 NTAPI Wow64NtCallExt::GetModuleLdrEntry64(const wchar_t* moduleName) {
        DWORD64 teb64Addr = GetTeb64();
        if ( teb64Addr == 0 ) {
            return 0;
        }

        TEB64 _teb64 = { 0 };
        memcpy64(&_teb64, teb64Addr, sizeof(TEB64));

        if ( _teb64.ProcessEnvironmentBlock == 0 ) {
            return 0;
        }

        PEB64 _peb64 = { 0 };
        memcpy64(&_peb64, _teb64.ProcessEnvironmentBlock, sizeof(PEB64));

        if ( _peb64.Ldr == 0 ) {
            return 0;
        }

        PEB_LDR_DATA64 _ldr64;
        memcpy64(&_ldr64, _peb64.Ldr, sizeof(PEB_LDR_DATA64));

        //head
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

    DWORD64 NTAPI Wow64NtCallExt::GetModuleBase64(const wchar_t* moduleName) {
        if ( !moduleName ) return 0;
        DWORD64 ldrEntry = GetModuleLdrEntry64(moduleName);
        if ( ldrEntry == 0 ) return 0;
        LDR_DATA_TABLE_ENTRY64 entry = { 0 };
        memcpy64(&entry, ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY64));
        return entry.DllBase;
    }

    #pragma warning(push)
    #pragma warning(disable: 4409)
    DWORD64 __cdecl Wow64NtCallExt::X64CallVa(DWORD64 func, int argC, ...) {
        if ( func == 0 ) return 0;

        va_list args;
        va_start(args, argC);
        Reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        Reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        Reg64 _r8 = { (argC > 0) ? argC--,va_arg(args, DWORD64) : 0 };
        Reg64 _r9 = { (argC > 0) ? argC--,va_arg(args, DWORD64) : 0 };
        Reg64 _rax = { 0 };

        Reg64 restArgs = { (DWORD64) args };
        Reg64 _argC = { (DWORD64) argC };
        DWORD back_esp = 0;
        WORD back_fs = 0;
        #ifdef _M_IX86
        __asm {
            mov back_fs, fs
            mov eax, 0x2B
            mov fs, ax

            mov back_esp, esp

            and esp, 0xFFFFFFF0

            //切换64位
            x64_start

            //压入前四个参数
            rex_w mov ecx, _rcx.dw[ 0 ]
            rex_w mov edx, _rdx.dw[ 0 ]

            push _r8.v
            x64_pop(r8)

            push _r9.v
            x64_pop(r9)

            rex_w mov eax, _argC.dw[ 0 ]
            //压入剩余参数
            test al, 1
            jnz _no_adjust
            sub esp, 8

            //遵循Windows参数从右到左的规则，将edi寄存器移到最后一个参数
            _no_adjust:
            push edi
            rex_w mov edi, restArgs.dw[ 0 ]
            rex_w test eax, eax
            jz _ls_e
            rex_w lea edi, dword ptr[ edi + 8 * eax - 8 ]

            _ls :
            rex_w test eax, eax
            jz _ls_e
            push dword ptr[ edi ]
            rex_w sub edi, 8
            rex_w sub eax, 1
            jmp _ls

            //预留栈空间
            _ls_e :
            rex_w sub esp, 0x20
            call func

            //恢复环境
            rex_w mov ecx, _argC.dw[ 0 ]
            rex_w lea esp, dword ptr[ esp + 8 * ecx + 0x20 ]
            pop edi
            rex_w mov _rax.dw[ 0 ], eax

            x64_end

            mov ax, ds
            mov ss, ax
            mov esp, back_esp
            mov ax, back_fs
            mov fs, ax
        }
        #endif
        va_end(args);
        return _rax.v;
    }
    #pragma warning(pop)

    VOID NTAPI Wow64NtCallExt::memcpy64(VOID* dest, DWORD64 src, SIZE_T sz) {
        if ( (nullptr == dest) || (0 == src) || (0 == sz) )
            return;

        #ifdef _M_IX86
        Reg64 _src = {
            src
        };
        __asm {
            x64_start

            push edi
            push esi

            mov edi, dest
            rex_w mov esi, dword ptr[ _src ]
            mov ecx, sz

            mov eax, ecx
            and eax, 3
            shr ecx, 2

            rep movsd
            test eax, eax
            je _remain_0

            cmp eax, 1
            je _remain_1

            movsw

            cmp eax, 2
            je _remain_0

            _remain_1 :
            movsb

            _remain_0 :
            pop esi
            pop edi

            x64_end
        }
        #endif
    }

    VOID NTAPI Wow64NtCallExt::memcpy64(DWORD64 dest, VOID* src, SIZE_T sz) {
        if ( (0 == dest) || (nullptr == src) || (0 == sz) )
            return;
        #ifdef _M_IX86
        Reg64 _dest = {
            dest
        };

        __asm {
            x64_start
            push edi
            push esi

            rex_w mov edi, dword ptr[ _dest ]
            mov esi, src
            mov ecx, sz

            mov eax, ecx
            and eax, 3 //计算除于4的余数
            shr ecx, 2 //计算除于4的商

            rep movsd //复制4字节块
            test eax, eax
            je _w_remain_0

            cmp eax, 1
            je _w_remain_1

            movsw
            cmp eax, 2
            je _w_remain_0

            _w_remain_1 :
            movsb

            _w_remain_0 :
            pop esi
            pop edi
            x64_end
        }
        #endif
    }

    DWORD64 NTAPI Wow64NtCallExt::GetNtdll64() {
        static DWORD64 _ntdll64 = 0;
        if ( _ntdll64 != 0 ) {
            return _ntdll64;
        }
        _ntdll64 = GetModuleBase64(L"ntdll.dll");
        return _ntdll64;
    }

    DWORD64 NTAPI Wow64NtCallExt::GetKernel64() {
        static DWORD64 _kernel64 = 0;
        if ( _kernel64 != 0 ) {
            return _kernel64;
        }

        DWORD64 LdrLoadDll = GetProcAddress64(GetNtdll64(), "LdrLoadDll");
        if ( !LdrLoadDll ) return 0;

        BYTE kernel32Str[ 64 ] = { 0 };
        MakeUTFStr<DWORD64>(L"kernel32.dll", kernel32Str);

        PEB64 _peb64 = { 0 };
        memcpy64(&_peb64, GetPeb64(), sizeof(PEB64));

        HANDLE hModule = GetModuleHandle(nullptr);
        IMAGE_NT_HEADERS* pInh = (IMAGE_NT_HEADERS*) ((BYTE*) hModule + ((IMAGE_DOS_HEADER*) hModule)->e_lfanew);
        WORD& subSystem = pInh->OptionalHeader.Subsystem;

        //backup subsystem value
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

        X64Call(LdrLoadDll, (DWORD64) 0, (DWORD64) 0, (DWORD64) kernel32Str, (DWORD64) &_kernel64);

        //restore subsystem value and process parameters
        if ( oldProctect ) {
            memcpy64(_peb64.ProcessParameters, &_upp64, sizeof(RTL_USER_PROCESS_PARAMETERS64));
            subSystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
            VirtualProtect(&subSystem, sizeof(WORD), oldProctect, &oldProctect);
        }

        return _kernel64;
    }

    DWORD64 NTAPI Wow64NtCallExt::LoadLibrary64(const wchar_t* moduleName) {
        if ( !moduleName ) return 0;

        DWORD64 hMod = GetModuleBase64(moduleName);
        if ( hMod != 0 ) return hMod;

        static DWORD64 pLoadLibraryW = 0;
        if ( !pLoadLibraryW ) {
            pLoadLibraryW = GetProcAddress64(GetKernel64(), "LoadLibraryW");
        }
        if ( !pLoadLibraryW ) return 0;

        return X64CallVa(pLoadLibraryW, 1, (DWORD64) moduleName);
    }

    DWORD NTAPI Wow64NtCallExt::GetProcAddress32(DWORD hMod, const char* funcName) {
        if ( !hMod || !funcName ) return 0;

        auto fnLdrGetProcedureAddress = (NTSTATUS(NTAPI*)(DWORD, DWORD, DWORD, DWORD*))(SIZE_T) GetLdrGetProcedureAddress32();
        if ( !fnLdrGetProcedureAddress ) return 0;

        BYTE fName[ 64 ] = { 0 };
        MakeANSIStr<DWORD>(funcName, fName);

        DWORD funcAddr = 0;

        NTSTATUS status = fnLdrGetProcedureAddress(hMod, (DWORD) fName, 0, &funcAddr);
        if ( NT_SUCCESS(status) ) {
            return funcAddr;
        }
        return 0;
    }

    DWORD NTAPI Wow64NtCallExt::GetModuleBase32(const wchar_t* moduleName) {
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

    DWORD NTAPI Wow64NtCallExt::GetTeb32() {
        DWORD _teb32 = 0;
        #ifdef _M_IX86
        _teb32 = __readfsdword(FIELD_OFFSET(NT_TIB, Self));
        #endif
        return _teb32;
    }

    DWORD NTAPI Wow64NtCallExt::GetPeb32() {
        DWORD _peb32 = 0;
        #ifdef _M_IX86
        _peb32 = __readfsdword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
        #endif
        return _peb32;
    }

    DWORD NTAPI Wow64NtCallExt::GetNtdll32() {
        static DWORD _ntdll32 = 0;
        if ( _ntdll32 != 0 ) {
            return _ntdll32;
        }
        _ntdll32 = GetModuleBase32(L"ntdll.dll");
        return _ntdll32;
    }

    DWORD Wow64NtCallExt::GetKernel32() {
        static DWORD _kernel32 = 0;
        if ( _kernel32 != 0 ) {
            return _kernel32;
        }
        _kernel32 = GetModuleBase32(L"kernel32.dll");
        return _kernel32;
    }

    DWORD NTAPI Wow64NtCallExt::GetLdrGetProcedureAddress32() {
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

    DWORD NTAPI Wow64NtCallExt::LoadLibrary32(const wchar_t* moduleName) {
        if ( !moduleName ) return 0;

        DWORD hMod = GetModuleBase32(moduleName);
        if ( hMod != 0 ) return hMod;

        static DWORD pLdrLoadDll32 = 0;
        if ( !pLdrLoadDll32 ) {
            pLdrLoadDll32 = GetProcAddress32(GetNtdll32(), "LdrLoadDll");
        }
        if ( !pLdrLoadDll32 ) return 0;

        BYTE buffer[ 64 ] = {
            0
        };
        MakeUTFStr < DWORD >(moduleName, buffer);

        DWORD hResult32 = 0;

        NTSTATUS status = ((NTSTATUS(NTAPI*)(DWORD, DWORD, DWORD, DWORD))(SIZE_T) pLdrLoadDll32)(NULL, NULL, (DWORD) (SIZE_T) buffer, (DWORD) (SIZE_T) &hResult32);
        if ( NT_SUCCESS(status) ) {
            return hResult32;
        }
        return 0;
    }

    DWORD64 NTAPI Wow64NtCallExt::GetLdrGetProcedureAddress() {
        DWORD64 dllBase = GetNtdll64();
        if ( !dllBase ) {
            return 0;
        }
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
            char funcName[ 256 ] = {
                0
            };
            memcpy64(funcName, dllBase + nameTable[ i ], sizeof(funcName) - 1);
            if ( strcmp(funcName, "LdrGetProcedureAddress") != 0 )
                continue;
            else
                return dllBase + rvaTable[ ordTable[ i ] ];
        }
        return 0;
    }

    DWORD64 NTAPI Wow64NtCallExt::GetTeb64() {
        Reg64 _teb64 = {
            0
        };
        #ifdef _M_IX86
        __asm {
            x64_start
            x64_push(r12);
            pop _teb64.dw[ 0 ]
            x64_end
        }
        #endif
        return _teb64.v;
    }

    DWORD64 NTAPI Wow64NtCallExt::GetPeb64() {
        Reg64 _peb64 = {
            0
        };
        #ifdef _M_IX86
        __asm {
            // 保存栈指针
            x64_start
            x64_push(r12);
            x64_pop(rax);
            rex_w mov eax, [ eax + 0x60 ]
            rex_w mov _peb64.dw[ 0 ], eax
            x64_end
        }
        #endif // _M_IX86
        return _peb64.v;
    }
}