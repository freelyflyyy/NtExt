#pragma once
#include "../../pch/stdafx.h"

namespace NtExt {
    /**
     * @namespace Resolver
     * @brief Resolves 32-bit and 64-bit loader metadata from a WoW64 process.
     * @details Provides Heaven's Gate based access to the native 64-bit address space while also exposing
     *          helpers for the 32-bit WoW64 layer.
     */
    namespace Resolver {

        #ifdef _M_IX86
        namespace detail {
            /**
             * @brief Architecture-specific export resolver implementation.
             * @param[in] hMod The base address of the target module.
             * @param[in] funcName The null-terminated exported symbol name.
             * @return The resolved 64-bit export address, or `0` on failure.
             */
            DWORD64 NTAPI GetProcAddress64Impl(_In_ DWORD64 hMod, _In_z_ const char* funcName);

            /**
             * @brief Internal implementation to resolve exported 32-bit function addresses.
             * @param[in] hMod The 32-bit module base address.
             * @param[in] funcName The function name.
             * @return The 32-bit function address.
             */
            DWORD NTAPI GetProcAddressImpl(_In_ DWORD hMod, _In_z_ const char* funcName);

            /**
             * @brief Packs a wide string into a UNICODE_STRING-compatible buffer layout.
             * @param[in] lpString The source wide string.
             * @param[out] outBuffer Receives the packed structure header and string payload.
             * @param[in] pointerSize The target pointer width in bytes.
             */
            VOID NTAPI MakeUTFStrImpl(_In_z_ LPCWSTR lpString, _Out_writes_bytes_(pointerSize + wcslen(lpString) * sizeof(WCHAR) + 16) LPBYTE outBuffer, _In_ SIZE_T pointerSize);

            /**
             * @brief Packs an ANSI string into an ANSI_STRING-compatible buffer layout.
             * @param[in] lpString The source ANSI string.
             * @param[out] outBuffer Receives the packed structure header and string payload.
             * @param[in] pointerSize The target pointer width in bytes.
             */
            VOID NTAPI MakeANSIStrImpl(_In_z_ LPCSTR lpString, _Out_writes_bytes_(pointerSize + strlen(lpString) + 16) LPBYTE outBuffer, _In_ SIZE_T pointerSize);

            extern std::unordered_map<std::string, DWORD64> _cache;
            extern std::shared_mutex _mutex;
            extern std::unordered_map<std::string, DWORD> _cache32;
            extern std::shared_mutex _mutex32;
        }

        /**
         * @brief Get the Nt function ssn and syscall commend addr.
         * @param[in] hMod The 64-bit base address of the module (e.g., ntdll).
         * @param[in] funcName The name of the NTAPI function.
         * @return A DWORD64 value where the high 16 bits represent the SSN, and the low 48 bits represent the syscall address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName);

        /**
         * @brief Get the module node in the 64-bit PEB LDR.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 64-bit memory address of the module's LDR_DATA_TABLE_ENTRY.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Get the 64-bit module base address.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 64-bit base address of the module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Get the 64-bit TEB (Thread Environment Block) address of the current process.
         * @return The 64-bit TEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetTeb64();

        /**
         * @brief Get the 64-bit PEB (Process Environment Block) address of the current process.
         * @return The 64-bit PEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetPeb64();

        /**
         * @brief Get the 64-bit ntdll.dll base address.
         * @return The 64-bit module base address of ntdll.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetNtdll64();

        /**
         * @brief Get the 64-bit kernel32.dll base address.
         * @return The 64-bit module base address of kernel32.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetKernel64();

        /**
         * @brief Manually loads a library into the 64-bit address space of the Wow64 process.
         * @param[in] moduleName The wide-character name of the module to load.
         * @return The 64-bit base address of the loaded module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Retrieves the 64-bit address of the LdrGetProcedureAddress function.
         * @return The 64-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetLdrGetProcedureAddress64();

        /**
         * @brief Copies memory from a 64-bit source address to a 32-bit destination buffer using a shellcode stub.
         * @param[out] dest The destination buffer in the 32-bit address space.
         * @param[in] src The 64-bit source address to copy from.
         * @param[in] sz The number of bytes to copy.
         */
        VOID NTAPI memcpy64(_Out_writes_bytes_all_(sz) VOID* dest, _In_ DWORD64 src, _In_ SIZE_T sz);

        /**
         * @brief Copies memory from a 32-bit source buffer to a 64-bit destination address using a shellcode stub.
         * @param[in] dest The 64-bit destination address to copy to.
         * @param[in] src The source buffer in the 32-bit address space.
         * @param[in] sz The number of bytes to copy.
         */
        VOID NTAPI memcpy64(_In_ DWORD64 dest, _In_reads_bytes_(sz) const VOID* src, _In_ SIZE_T sz);

        /**
         * @brief Retrieves the 32-bit base memory address of a loaded module.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 32-bit base address of the module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetModuleBase32(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Gets the 32-bit address of the Thread Environment Block (TEB).
         * @return The 32-bit TEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetTeb32();

        /**
         * @brief Gets the 32-bit address of the Process Environment Block (PEB).
         * @return The 32-bit PEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetPeb32();

        /**
         * @brief Retrieves the 32-bit base address of ntdll.dll.
         * @return The 32-bit base address of ntdll.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetNtdll32();

        /**
         * @brief Retrieves the 32-bit base address of kernel32.dll.
         * @return The 32-bit base address of kernel32.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetKernel32();

        /**
         * @brief Retrieves the 32-bit address of the LdrGetProcedureAddress function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetLdrGetProcedureAddress32();

        /**
         * @brief Manually loads a library into the 32-bit address space.
         * @param[in] moduleName The wide-character name of the module to load.
         * @return The 32-bit base address of the loaded module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI LoadLibrary32(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Constructs a UNICODE_STRING-like structure in the provided buffer.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated wide string to package.
         * @param[out] outBuffer The pre-allocated buffer to hold the structure header and string data.
         */
        template<typename T>
        inline VOID MakeUTFStr(_In_z_ LPCWSTR lpString, _Out_writes_bytes_all_(sizeof(T) + wcslen(lpString) * 2 + 16) LPBYTE outBuffer) {
            detail::MakeUTFStrImpl(lpString, outBuffer, sizeof(T));
        }

        /**
         * @brief Converts an ANSI string to a wide string and constructs a UNICODE_STRING-like structure.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated ANSI string to convert.
         * @param[out] outUnicodeStr The pre-allocated output buffer for the resulting structure.
         */
        template<typename T>
        inline VOID MakeUTFStr(_In_z_ LPCSTR lpString, _Out_writes_bytes_(sizeof(T) + (MultiByteToWideChar(CP_ACP, 0, lpString, -1, NULL, 0) - 1) * sizeof(WCHAR) + 16) LPBYTE outUnicodeStr) {
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
        inline VOID MakeANSIStr(_In_z_ LPCSTR lpString, _Out_writes_bytes_all_(sizeof(T) + strlen(lpString) + 16) LPBYTE outBuffer) {
            detail::MakeANSIStrImpl(lpString, outBuffer, sizeof(T));
        }

        /**
         * @brief Converts a wide string to an ANSI string and constructs an ANSI_STRING-like structure.
         * @tparam T The pointer type (DWORD for 32-bit builds, DWORD64 for 64-bit builds).
         * @param[in] lpString The null-terminated wide string to convert.
         * @param[out] outAnsiStr The pre-allocated output buffer for the resulting structure.
         */
        template<typename T>
        inline VOID MakeANSIStr(_In_z_ LPCWSTR lpString, _Out_writes_bytes_(sizeof(T) + (WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL) - 1) + 16) LPBYTE outAnsiStr) {
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
            DWORD64 IsCached64(_In_ const std::string& funcName);

        /**
         * @brief Retrieves the 64-bit memory address of an exported function, using an internal cache to optimize repeated calls.
         * @param[in] hMod The 64-bit base address of the module containing the function.
         * @param[in] funcName The name of the exported function.
         * @return The 64-bit address of the function, or 0 if resolution fails.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ DWORD64 hMod, _In_ const std::string& funcName);

        /**
         * @brief Retrieves the 64-bit memory address of an exported function by providing the module name.
         * @param[in] moduleName The wide-character name of the target module (e.g., L"kernel32.dll").
         * @param[in] funcName The name of the exported function.
         * @return The 64-bit address of the function, or 0 if resolution fails.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ const std::wstring& moduleName, _In_ const std::string& funcName);

        /**
         * @brief Retrieves the 64-bit memory address of an exported function, defaulting to searching within ntdll.dll.
         * @param[in] funcName The name of the exported function expected to be in ntdll.dll.
         * @return The 64-bit address of the function, or 0 if resolution fails.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 GetProcAddress64(_In_ const std::string& funcName);

        /**
         * @brief Thread-safely checks if a 32-bit function's memory address is already cached.
         * @param[in] funcName The name of the target function.
         * @return The cached 32-bit address if found, otherwise 0.
         */
        _Success_(return != 0)
            DWORD IsCached32(_In_ const std::string& funcName);

        /**
         * @brief Retrieves the 32-bit memory address of an exported function, using an internal cache to optimize repeated calls.
         * @param[in] hMod The 32-bit base address of the module containing the function.
         * @param[in] funcName The name of the exported function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ DWORD hMod, _In_ const std::string& funcName);

        /**
         * @brief Retrieves the 32-bit memory address of an exported function by providing the module name.
         * @param[in] moduleName The wide-character name of the target module.
         * @param[in] funcName The name of the exported function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ const std::wstring& moduleName, _In_ const std::string& funcName);

        /**
         * @brief Retrieves the 32-bit memory address of an exported function, defaulting to searching within the 32-bit ntdll.dll.
         * @param[in] funcName The name of the exported function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ const std::string& funcName);
        #endif
    }
}
