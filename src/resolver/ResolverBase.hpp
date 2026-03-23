#pragma once
#include "../pch/stdafx.h"

namespace NtExt {

    class ResolverBase {
        public:
        virtual ~ResolverBase() = default;

        ResolverBase(const ResolverBase&) = delete;
        ResolverBase& operator=(const ResolverBase&) = delete;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetTeb64() = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetPeb64() = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetNtdll64() = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetKernel64() = 0;

        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) = 0;

        template<typename T>
        VOID MakeUTFStr(_In_z_ LPCWSTR lpString, _Out_writes_bytes_all_(sizeof(T) + wcslen(lpString) * 2 + 16) LPBYTE outBuffer) {
            _MakeUTFStrVa(lpString, outBuffer, sizeof(T));
        }

        template<typename T>
        VOID MakeUTFStr(_In_z_ LPCSTR lpString, _Out_ LPBYTE outUnicodeStr) {
            int len = MultiByteToWideChar(CP_ACP, 0, lpString, -1, NULL, 0);
            std::wstring wStr(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, lpString, -1, wStr.data(), len);
            MakeUTFStr<T>(wStr.c_str(), outUnicodeStr);
        }

        template<typename T>
        VOID MakeANSIStr(_In_z_ LPCSTR lpString, _Out_writes_bytes_all_(sizeof(T) + strlen(lpString) + 16) LPBYTE outBuffer) {
            _MakeANSIStrVa(lpString, outBuffer, sizeof(T));
        }

        template<typename T>
        VOID MakeANSIStr(_In_z_ LPCWSTR lpString, _Out_ LPBYTE outAnsiStr) {
            int len = WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL);
            std::string aStr(len, '\0');
            WideCharToMultiByte(CP_ACP, 0, lpString, -1, aStr.data(), len, NULL, NULL);
            MakeANSIStr<T>(aStr.c_str(), outAnsiStr);
        }

        _Success_(return != 0)
            DWORD64 IsCached64(_In_ const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex);
            auto it = _cache.find(funcName);
            if ( it != _cache.end() ) return it->second;
            return 0;
        }

        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ DWORD64 hMod, _In_ const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD64 procAddr = _GetProcAddress64(hMod, funcName.data());
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex);
                _cache[ funcName ] = procAddr;
            }
            return procAddr;
        }

        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ const std::wstring& moduleName, _In_ const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            DWORD64 hMod = GetModuleBase64(moduleName.data());
            if ( hMod == 0 ) return 0;
            return GetProcAddress64(hMod, funcName);
        }

        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            return GetProcAddress64(GetNtdll64(), funcName);
        }

        private:
        virtual DWORD64 NTAPI _GetProcAddress64(_In_ DWORD64 hMod, _In_z_ const char* funcName) = 0;

        VOID NTAPI _MakeUTFStrVa(_In_z_ LPCWSTR lpString, _Out_ LPBYTE outBuffer, _In_ SIZE_T pointerSize);
        VOID NTAPI _MakeANSIStrVa(_In_z_ LPCSTR lpString, _Out_ LPBYTE outBuffer, _In_ SIZE_T pointerSize);

        protected:
        ResolverBase() = default;

        std::unordered_map<std::string, DWORD64> _cache;
        std::shared_mutex _mutex;
    };
}