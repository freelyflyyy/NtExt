#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
	#ifdef _WIN64
	/**
	 * @class X64Call
	 * @brief Dynamically executes a standard function at a specified 64-bit memory address.
	 * @details Uses the x64 calling convention to pass arguments and jump to the target address.
	 */
	class X64Call : public X64Invoker {
		private:
		DWORD64 _funcAddr;
		DWORD64 _args[ 16 ] = { 0 };

		public:
		X64Call(_In_ DWORD64 funcAddr) : _funcAddr(funcAddr) {}

		/**
		 * @brief Overloaded call operator that accepts a variable number of arguments, formats them, and triggers execution.
		 * @tparam Args Variadic template arguments representing the parameters for the target function.
		 * @param args The arguments to be passed to the function (up to 16 arguments).
		 * @return The 64-bit return value from the executed function.
		 */
		template<typename... Args>
		_Check_return_ 
			DWORD64 operator()(Args... args) {
			memset(_args, 0, sizeof(_args));
			if constexpr ( sizeof...(args) > 0 ) {
				DWORD i = 0;
				((_args[ i++ ] = (DWORD64) args), ...);
			}
			return Invoke();
		}

		protected:
		VOID onPrepareEnv(_Inout_ std::string* pShell) override {
			InjectPrepareEnv(pShell, _args);
		}

		VOID onEmitOpcode(_Inout_ std::string* pShell) override {
			BYTE call_stub[] = {
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xD0
			};
			*(DWORD64*) (call_stub + 2) = _funcAddr;
			pShell->append((char*) call_stub, sizeof(call_stub));
		}
	};
	#endif
}