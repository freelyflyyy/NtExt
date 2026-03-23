#pragma once
#include "../ResolverBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Resolver : public ResolverBase {
		public:
		static X64Resolver& GetInstance() {
			static X64Resolver instance;
			return instance;
		}

		~X64Resolver() override = default;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetTeb64() override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetPeb64() override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetNtdll64() override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetKernel64() override;

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) override;

		protected:
		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI _GetProcAddress64(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

		private:
		X64Resolver() = default;
	};
	#endif
}