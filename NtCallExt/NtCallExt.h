#include "NtApi.h"

#define EMIT(a) __asm __emit (a)

// Switch to 64 bit mode
#define x64_start \
		EMIT(0x6A) EMIT(0x33)                         /* push 0x33             */ \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)    /* call $+5              */ \
		EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05)   /* add dword [esp], 5    */ \
		EMIT(0xCB)                                    /* retf                  */

// back to 32 bit mode
#define x64_end \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                     /* call $+5              */  \
		EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(0x04) EMIT(0x23) EMIT(0) EMIT(0) EMIT(0) /* mov dword [rsp+4], 0x23*/ \
		EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x0D)                                    /* add dword [rsp], 0x0D */  \
		EMIT(0xCB)                                                                     /* retf                  */

#define rex_w EMIT(0x48) __asm

#define rax  0
#define rcx  1
#define rdx  2
#define rbx  3
#define rsp  4
#define rbp  5
#define rsi  6
#define rdi  7
#define r8   8
#define r9   9
#define r10  10
#define r11  11
#define r12  12
#define r13  13
#define r14  14
#define r15  15

// push 64 register
#define x64_push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))

// pop 64 register
#define x64_pop(r)  EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

union Reg64 {
	DWORD64 v;
	DWORD dw[ 2 ];
};

class NTEX_API NtCallExt {
	public:
	virtual ~NtCallExt() = default;
	virtual DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) = 0;
	virtual DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) = 0;
	virtual DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) = 0;
	virtual DWORD64 NTAPI GetTeb64() = 0;
	virtual DWORD64 NTAPI GetPeb64() = 0;
	virtual DWORD64 NTAPI GetNtdll64() = 0;
	virtual DWORD64 NTAPI GetKernel64() = 0;
	virtual DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) = 0;
	VOID NTAPI MakeUTFStrVa(LPCWSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize);
	VOID NTAPI MakeANSIStrVa(LPCSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize);

	template<typename T>
	VOID MakeUTFStr(LPCWSTR lpString, LPBYTE outBuffer) {
		MakeUTFStrVa(lpString, outBuffer, sizeof(T));
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
		MakeANSIStrVa(lpString, outBuffer, sizeof(T));
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

	protected:
	std::unordered_map<std::string, DWORD64> _cache;
	std::shared_mutex _mutex;
};

class NTEX_API X64NtCallExt : public NtCallExt {
	public:
	DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) override;
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
			return ERROR_INVALID_ADDRESS;
		}
		return ((NTSTATUS(NTAPI*)(Args...))funcAddr)(std::forward<Args>(args)...);
	}
};

class NTEX_API Wow64NtCallExt : public NtCallExt {
	public:
	DWORD64 NTAPI GetProcAddress64(DWORD64 hMod, const char* funcName) override;
	DWORD64 NTAPI GetModuleLdrEntry64(const wchar_t* moduleName) override;
	DWORD64 NTAPI GetModuleBase64(const wchar_t* moduleName) override;
	DWORD64 NTAPI GetTeb64() override;
	DWORD64 NTAPI GetPeb64() override;
	DWORD64 NTAPI GetNtdll64() override;
	DWORD64 NTAPI GetKernel64() override;
	DWORD64 NTAPI LoadLibrary64(const wchar_t* moduleName) override;
	DWORD64 NTAPI GetLdrGetProcedureAddress();
	DWORD64 __cdecl X64CallVa(DWORD64 funcAddr, int argCount, ...);
	VOID NTAPI memcpy64(VOID* dest, DWORD64 src, SIZE_T sz);
	VOID NTAPI memcpy64(DWORD64 dest, VOID* src, SIZE_T sz);

	template<typename... Args>
	NTSTATUS X64Call(const DWORD64& funcAddr, Args&&... args) {
		if ( !funcAddr ) return ERROR_INVALID_ADDRESS;
		return (NTSTATUS) X64CallVa((DWORD64) funcAddr, (int) sizeof...(Args), (DWORD64) std::forward<Args>(args)...);
	}

	//32bit native functions
	DWORD NTAPI GetProcAddress32(DWORD hMod, const char* funcName);
	DWORD NTAPI GetModuleBase32(const wchar_t* moduleName);
	DWORD NTAPI GetTeb32();
	DWORD NTAPI GetPeb32();
	DWORD NTAPI GetNtdll32();
	DWORD NTAPI GetKernel32();
	DWORD NTAPI GetLdrGetProcedureAddress32();
	DWORD NTAPI LoadLibrary32(const wchar_t* moduleName);

	DWORD IsCached32(const std::string& funcName) {
		std::shared_lock<std::shared_mutex> lock(_mutex32);
		auto it = _cache32.find(funcName);
		if ( it != _cache32.end() ) {
			return it->second;
		}
		return 0;
	}

	DWORD GetFunc32(DWORD hMod, const std::string& funcName) {
		if ( auto addr = IsCached32(funcName) ) return addr;
		if ( hMod == 0 ) return 0;
		DWORD procAddr = GetProcAddress32(hMod, funcName.c_str());
		if ( procAddr ) {
			std::unique_lock<std::shared_mutex> lock(_mutex32);
			_cache32[ funcName ] = procAddr;
		}
		return procAddr;
	}

	DWORD GetFunc32(const std::wstring& moduleName, const std::string& funcName) {
		if ( auto addr = IsCached32(funcName) ) return addr;
		DWORD hMod = GetModuleBase32(moduleName.c_str());
		if ( hMod == 0 ) hMod = LoadLibrary32(moduleName.c_str());
		if ( hMod == 0 ) return 0;
		return GetFunc32(hMod, funcName);
	}

	DWORD GetFunc32(const std::string& funcName) {
		if ( auto addr = IsCached32(funcName) ) return addr;
		return GetFunc32(GetNtdll32(), funcName);
	}

	private:
	std::unordered_map<std::string, DWORD> _cache32;
	std::shared_mutex _mutex32;
};

#ifdef _WIN64
inline X64NtCallExt NtCallExt;
#else
inline Wow64NtCallExt NtCallExt;
#endif

#define GET_FUNC64(moduleName, funcName) (NtCallExt.GetFunc64(moduleName, funcName))
#define GET_NTFUNC64(funcName) (NtCallExt.GetFunc64(funcName))
#define CALL64_FUNC(funcName, ...) (NtCallExt.X64Call(funcName, __VA_ARGS__))
#define LOADLIB64(moduleName) (NtCallExt.LoadLibrary64(moduleName))

#define GET_FUNC(moduleName, funcName) GET_FUNC64(moduleName, funcName)
#define GET_NTFUNC(funcName) GET_NTFUNC64(funcName)
#define CALL_FUNC(funcName, ...) CALL64_FUNC(funcName, __VA_ARGS__)

#ifndef _WIN64
#define GET_FUNC32(moduleName, funcName) (NtCallExt.GetFunc32(moduleName, funcName))
#define GET_NTFUNC32(funcName) (NtCallExt.GetFunc32(funcName))
#define LOADLIB32(moduleName) (NtCallExt.LoadLibrary32(moduleName))
#else
/*
To prevent potential errors, the call of 32 - bit functions
in a 64 - bit system is redirected back to 64 - bit functions
*/
#define GET_FUNC32(moduleName, funcName) GET_FUNC(moduleName, funcName)
#define GET_NTFUNC32(funcName) GET_NTFUNC(funcName)
#define LOADLIB32(moduleName) LOADLIB64(moduleName)
#endif
