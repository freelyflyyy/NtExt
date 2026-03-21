#pragma once
#include "pch/stdafx.h"
#include "internal/NtApi.h"

namespace NtExt {

    class NtCallExt {
        public:
        virtual ~NtCallExt() = default;
        virtual DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) = 0;
        virtual DWORD64 NTAPI GetSyscallNumber64(DWORD64 hMod, const char* funcName) = 0;
        virtual DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) = 0;
        virtual DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) = 0;
        virtual DWORD64 NTAPI GetTeb64() = 0;
        virtual DWORD64 NTAPI GetPeb64() = 0;
        virtual DWORD64 NTAPI GetNtdll64() = 0;
        virtual DWORD64 NTAPI GetKernel64() = 0;
        virtual DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) = 0;

        template<typename... Args>
        NTSTATUS X64Call(const DWORD64& funcAddr, Args&&... args) {
            if ( !funcAddr ) return STATUS_INVALID_ADDRESS;

            auto _buildCallAction = [funcAddr] (std::string& _shellcode) {
                BYTE call_stub[] = {
                    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, funcAddr
                    0xFF, 0xD0                                                  // call rax
                };
                *(DWORD64*) (call_stub + 2) = funcAddr;
                _shellcode.append((char*) call_stub, sizeof(call_stub));
            };
            constexpr DWORD safeSize = sizeof...(Args) < 4 ? 4 : sizeof...(Args);
            const DWORD64 _argArray[ safeSize ] = { (DWORD64) std::forward<Args>(args)... };

            return (NTSTATUS) _X64BuildExecute(_buildCallAction, _argArray, sizeof...(Args));
        }

        template<typename... Args>
        NTSTATUS X64SysCall(const WORD& ssn, Args&&... args) {
            if ( !ssn ) return STATUS_INVALID_PARAMETER;

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

            constexpr DWORD safeSize = sizeof...(Args) < 4 ? 4 : sizeof...(Args);
            const DWORD64 _argArray[ safeSize ] = { (DWORD64) std::forward<Args>(args)... };

            return (NTSTATUS) _X64BuildExecute(_buildSysCallAction, _argArray, sizeof...(Args));
        }

        template<typename T>
        VOID MakeUTFStr(LPCWSTR lpString, LPBYTE outBuffer) {
            _MakeUTFStrVa(lpString, outBuffer, sizeof(T));
        }

        template<typename T>
        VOID MakeUTFStr(LPCSTR lpString, LPBYTE outUnicodeStr) {
            int len = MultiByteToWideChar(CP_ACP, 0, lpString, -1, NULL, 0);
            std::wstring wStr(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, lpString, -1, wStr.data(), len);
            MakeUTFStr<T>(wStr.c_str(), outUnicodeStr);
        }

        template<typename T>
        VOID MakeANSIStr(LPCSTR lpString, LPBYTE outBuffer) {
            _MakeANSIStrVa(lpString, outBuffer, sizeof(T));
        }

        template<typename T>
        VOID MakeANSIStr(LPCWSTR lpString, LPBYTE outAnsiStr) {
            int len = WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL);
            std::string aStr(len, '\0');
            WideCharToMultiByte(CP_ACP, 0, lpString, -1, aStr.data(), len, NULL, NULL);
            MakeANSIStr<T>(aStr.c_str(), outAnsiStr);
        }

        DWORD64 IsCached64(const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex);
            auto it = _cache.find(funcName);
            if ( it != _cache.end() ) {
                return it->second;
            }
            return 0;
        }

        DWORD64 GetFunc64(DWORD64 hMod, const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;

            if ( hMod == 0 ) return 0;

            DWORD64 procAddr = GetProcAddress64(hMod, funcName.data());

            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex);
                _cache[ funcName ] = procAddr;
            }
            return procAddr;
        }

        DWORD64 GetFunc64(const std::wstring& moduleName, const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;

            DWORD64 hMod = GetModuleBase64(moduleName.data());
            if ( hMod == 0 ) return 0;

            return GetFunc64(hMod, funcName);
        }

        DWORD64 GetFunc64(const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            return GetFunc64(GetNtdll64(), funcName);
        }

        private:
        VOID NTAPI _MakeUTFStrVa(LPCWSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize);
        VOID NTAPI _MakeANSIStrVa(LPCSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize);
        virtual DWORD64 NTAPI _X64BuildExecute(std::function<void(std::string&)> _shellcode, const DWORD64* _pParam, const DWORD& _argC) = 0;
        virtual DWORD64 NTAPI _X64DisptachExecute(std::string _shellcode) = 0;

        protected:
        std::unordered_map<std::string, DWORD64> _cache;
        std::shared_mutex _mutex;
    };
}
#include "Wow64NtCallExt.h"
#include "X64NtCallExt.h"
