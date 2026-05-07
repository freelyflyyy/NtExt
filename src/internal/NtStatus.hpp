#pragma once
#include "NtBase.hpp"

#include <string>
#include <utility>

namespace NtExt {

	/**
	 * @brief Represents an NTSTATUS code paired with an optional message.
	 */
	class [[nodiscard]] NtStatus {
		public:
		NtStatus() : _code(STATUS_UNSUCCESSFUL), _message(L"Unknown error.") {
		}

		explicit NtStatus(_In_ NTSTATUS Code, std::wstring Message = L"")
			: _code(Code), _message(std::move(Message)) {
		}

		_Check_return_
			static NtStatus Success(std::wstring Message = L"") {
			return NtStatus(STATUS_SUCCESS, std::move(Message));
		}

		_Check_return_
			static NtStatus success(std::wstring Message = L"") {
			return Success(std::move(Message));
		}

		_Check_return_
			static NtStatus Failure(_In_ NTSTATUS Code, std::wstring Message = L"") {
			return NtStatus(Code, std::move(Message));
		}

		_Check_return_
			static NtStatus fail(_In_ NTSTATUS Code, std::wstring Message = L"") {
			return Failure(Code, std::move(Message));
		}

		_Check_return_
			static NtStatus Failure(std::wstring Message) {
			return NtStatus(STATUS_UNSUCCESSFUL, std::move(Message));
		}

		_Check_return_
			static NtStatus fail(std::wstring Message) {
			return Failure(std::move(Message));
		}

		_Check_return_
			static NtStatus Failure(const NtStatus& StatusValue) {
			return NtStatus(StatusValue.Code(), StatusValue.Message());
		}

		_Check_return_
			static NtStatus fail(const NtStatus& StatusValue) {
			return Failure(StatusValue);
		}

		_Check_return_
			NTSTATUS Code() const noexcept {
			return _code;
		}

		_Check_return_
			NTSTATUS code() const noexcept {
			return Code();
		}

		_Check_return_
			const std::wstring& Message() const noexcept {
			return _message;
		}

		_Check_return_
			const std::wstring& message() const noexcept {
			return Message();
		}

		_Check_return_
			bool Succeeded() const noexcept {
			return NT_SUCCESS(_code);
		}

		_Check_return_
			bool isSuccess() const noexcept {
			return Succeeded();
		}

		_Check_return_
			bool Failed() const noexcept {
			return !Succeeded();
		}

		_Check_return_
			bool isFailure() const noexcept {
			return Failed();
		}

		_Check_return_
			explicit operator bool() const noexcept {
			return Succeeded();
		}

		private:
		NTSTATUS _code;
		std::wstring _message;
	};

}
