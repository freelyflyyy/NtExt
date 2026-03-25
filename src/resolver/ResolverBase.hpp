#pragma once
#include "../pch/stdafx.h"

namespace NtExt {

    class ResolverBase {
        public:
        virtual ~ResolverBase() = default;

        ResolverBase(const ResolverBase&) = delete;
        ResolverBase& operator=(const ResolverBase&) = delete;

        /**
         * @brief Dynamically locates the System Service Number (SSN) for an NTAPI function.
         * @param[in] hMod The base address of the module (e.g., ntdll.dll).
         * @param[in] funcName The name of the NTAPI function (e.g., "NtReadVirtualMemory").
         * @return A 64-bit value where the high 16 bits contain the SSN, and the low 48 bits contain the syscall instruction address. Returns 0 on failure.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) = 0;

        /**
         * @brief Retrieves the LDR_DATA_TABLE_ENTRY for a loaded module by traversing the PEB.
         * @param[in] moduleName The wide-character name of the module (e.g., L"ntdll.dll").
         * @return The 64-bit memory address of the module's LDR entry. Returns 0 if not found.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) = 0;

        /**
         * @brief Retrieves the 64-bit base memory address of a loaded module.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 64-bit base address of the module. Returns 0 if not found.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) = 0;

        /**
         * @brief Gets the 64-bit address of the Thread Environment Block (TEB).
         * @return The 64-bit address of the TEB.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetTeb64() = 0;

        /**
         * @brief Gets the 64-bit address of the Process Environment Block (PEB).
         * @return The 64-bit address of the PEB.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetPeb64() = 0;

        /**
         * @brief Retrieves the 64-bit base address of ntdll.dll.
         * @return The 64-bit base address of ntdll.dll.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetNtdll64() = 0;

        /**
         * @brief Retrieves the 64-bit base address of kernel32.dll.
         * @return The 64-bit base address of kernel32.dll.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI GetKernel64() = 0;

        /**
         * @brief Manually loads a library into the 64-bit address space using LdrLoadDll.
         * @param[in] moduleName The wide-character name of the module to load.
         * @return The 64-bit base address of the loaded module. Returns 0 on failure.
         */
        _Check_return_ _Success_(return != 0)
            virtual DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) = 0;

        /**
         * @brief Constructs a UNICODE_STRING-like structure in the provided buffer.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated wide string to package.
         * @param[out] outBuffer The pre-allocated buffer to hold the structure header and string data.
         */
        template<typename T>
        VOID MakeUTFStr(_In_z_ LPCWSTR lpString, _Out_writes_bytes_all_(sizeof(T) + wcslen(lpString) * 2 + 16) LPBYTE outBuffer) {
            MakeUTFStrImpl(lpString, outBuffer, sizeof(T));
        }

        /**
         * @brief Converts an ANSI string to a wide string and constructs a UNICODE_STRING-like structure.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated ANSI string to convert.
         * @param[out] outUnicodeStr The pre-allocated output buffer for the resulting structure.
         */
        template<typename T>
        VOID MakeUTFStr(_In_z_ LPCSTR lpString, _Out_ LPBYTE outUnicodeStr) {
            int len = MultiByteToWideChar(CP_ACP, 0, lpString, -1, NULL, 0);
            std::wstring wStr(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, lpString, -1, wStr.data(), len);
            MakeUTFStr<T>(wStr.c_str(), outUnicodeStr);
        }

        /**
         * @brief Constructs an ANSI_STRING-like structure in the provided buffer.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated ANSI string to package.
         * @param[out] outBuffer The pre-allocated buffer to hold the structure header and string data.
         */
        template<typename T>
        VOID MakeANSIStr(_In_z_ LPCSTR lpString, _Out_writes_bytes_all_(sizeof(T) + strlen(lpString) + 16) LPBYTE outBuffer) {
            MakeANSIStrImpl(lpString, outBuffer, sizeof(T));
        }

        /**
         * @brief Converts a wide string to an ANSI string and constructs an ANSI_STRING-like structure.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated wide string to convert.
         * @param[out] outAnsiStr The pre-allocated output buffer for the resulting structure.
         */
        template<typename T>
        VOID MakeANSIStr(_In_z_ LPCWSTR lpString, _Out_ LPBYTE outAnsiStr) {
            int len = WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL);
            std::string aStr(len, '\0');
            WideCharToMultiByte(CP_ACP, 0, lpString, -1, aStr.data(), len, NULL, NULL);
            MakeANSIStr<T>(aStr.c_str(), outAnsiStr);
        }

        /**
         * @brief Thread-safely checks if a function's memory address is already cached.
         * @param[in] funcName The name of the target function.
         * @return The cached 64-bit address if found, otherwise 0.
         */
        _Success_(return != 0)
            DWORD64 IsCached64(_In_ const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex);
            auto it = _cache.find(funcName);
            if ( it != _cache.end() ) return it->second;
            return 0;
        }

        /**
         * @brief Retrieves the 64-bit memory address of an exported function, using an internal cache to optimize repeated calls.
         * @param[in] hMod The 64-bit base address of the module containing the function.
         * @param[in] funcName The name of the exported function.
         * @return The 64-bit address of the function, or 0 if resolution fails.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ DWORD64 hMod, _In_ const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD64 procAddr = GetProcAddress64Impl(hMod, funcName.data());
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex);
                _cache[ funcName ] = procAddr;
            }
            return procAddr;
        }

        /**
         * @brief Retrieves the 64-bit memory address of an exported function by providing the module name.
         * @param[in] moduleName The wide-character name of the target module (e.g., L"kernel32.dll").
         * @param[in] funcName The name of the exported function.
         * @return The 64-bit address of the function, or 0 if resolution fails.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ const std::wstring& moduleName, _In_ const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            DWORD64 hMod = GetModuleBase64(moduleName.data());
            if ( hMod == 0 ) return 0;
            return GetProcAddress64(hMod, funcName);
        }

        /**
         * @brief Retrieves the 64-bit memory address of an exported function, defaulting to searching within ntdll.dll.
         * @param[in] funcName The name of the exported function expected to be in ntdll.dll.
         * @return The 64-bit address of the function, or 0 if resolution fails.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ const std::string& funcName) {
            if ( auto addr = IsCached64(funcName) ) return addr;
            return GetProcAddress64(GetNtdll64(), funcName);
        }

        private:
        virtual DWORD64 NTAPI GetProcAddress64Impl(_In_ DWORD64 hMod, _In_z_ const char* funcName) = 0;

        VOID NTAPI MakeUTFStrImpl(_In_z_ LPCWSTR lpString, _Out_ LPBYTE outBuffer, _In_ SIZE_T pointerSize);
        VOID NTAPI MakeANSIStrImpl(_In_z_ LPCSTR lpString, _Out_ LPBYTE outBuffer, _In_ SIZE_T pointerSize);

        protected:
        ResolverBase() = default;

        std::unordered_map<std::string, DWORD64> _cache;
        std::shared_mutex _mutex;
    };
}