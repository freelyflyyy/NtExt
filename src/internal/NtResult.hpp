#pragma once
#include "NtStatus.hpp"

#include <optional>
#include <string>
#include <utility>

namespace NtExt {

	/**
	 * @brief Represents an operation result with a value on success.
	 * @tparam T Value type carried by a successful result.
	 */
	template<typename T>
	class NtResult : public NtStatus {
		public:
		explicit NtResult() : NtStatus(), _value(std::nullopt) {
		}

		explicit NtResult(const NtStatus& StatusValue)
			: NtStatus(StatusValue.Code(), StatusValue.Message()), _value(std::nullopt) {
		}

		_Check_return_
			static NtResult<T> Success(const T& Value, std::wstring Message = L"") {
			return NtResult<T>(STATUS_SUCCESS, std::move(Message), Value);
		}

		_Check_return_
			static NtResult<T> success(const T& Value, std::wstring Message = L"") {
			return Success(Value, std::move(Message));
		}

		_Check_return_
			static NtResult<T> Success(T&& Value, std::wstring Message = L"") {
			return NtResult<T>(STATUS_SUCCESS, std::move(Message), std::move(Value));
		}

		_Check_return_
			static NtResult<T> success(T&& Value, std::wstring Message = L"") {
			return Success(std::move(Value), std::move(Message));
		}

		_Check_return_
			static NtResult<T> Failure(_In_ NTSTATUS Code, std::wstring Message = L"") {
			return NtResult<T>(Code, std::move(Message), std::nullopt);
		}

		_Check_return_
			static NtResult<T> fail(_In_ NTSTATUS Code, std::wstring Message = L"") {
			return Failure(Code, std::move(Message));
		}

		_Check_return_
			static NtResult<T> Failure(std::wstring Message) {
			return NtResult<T>(STATUS_UNSUCCESSFUL, std::move(Message), std::nullopt);
		}

		_Check_return_
			static NtResult<T> fail(std::wstring Message) {
			return Failure(std::move(Message));
		}

		_Check_return_
			static NtResult<T> Failure(const NtStatus& StatusValue) {
			return NtResult<T>(StatusValue);
		}

		_Check_return_
			static NtResult<T> fail(const NtStatus& StatusValue) {
			return Failure(StatusValue);
		}

		_Check_return_
			bool HasValue() const noexcept {
			return _value.has_value();
		}

		_Check_return_
			bool IsEmpty() const noexcept {
			return !_value.has_value();
		}

		_Check_return_
			bool isEmpty() const noexcept {
			return IsEmpty();
		}

		_Check_return_
			T& Value() {
			return _value.value();
		}

		_Check_return_
			T& value() {
			return Value();
		}

		_Check_return_
			const T& Value() const {
			return _value.value();
		}

		_Check_return_
			const T& value() const {
			return Value();
		}

		_Check_return_
			T ValueOr(const T& DefaultValue) const {
			return _value.has_value() ? _value.value() : DefaultValue;
		}

		_Check_return_
			T valueOr(const T& DefaultValue) const {
			return ValueOr(DefaultValue);
		}

		_Check_return_
			T* operator->() {
			return &_value.value();
		}

		_Check_return_
			const T* operator->() const {
			return &_value.value();
		}

		_Check_return_
			T& operator*() {
			return _value.value();
		}

		_Check_return_
			const T& operator*() const {
			return _value.value();
		}

		explicit operator T() && {
			return std::move(_value.value());
		}

		explicit operator T&() {
			return _value.value();
		}

		explicit operator const T&() const {
			return _value.value();
		}

		private:
		NtResult(_In_ NTSTATUS Code, std::wstring Message, std::optional<T> Value)
			: NtStatus(Code, std::move(Message)), _value(std::move(Value)) {
		}

		std::optional<T> _value;
	};

}
