/**
 * @file NtExt.hpp
 * @brief Main inclusion header for the NtExt library.
 * @details This file serves as the primary entry point.
 * It handles automatic architecture detection (x86 vs x64) and includes all essential
 * components: precompiled headers, address resolvers, and dynamic code invokers.
 * By including this single file, users gain immediate access to advanced Windows
 * internal features, including Heaven's Gate, dynamic Syscall execution, and
 * manual PEB/TEB parsing without relying on highly monitored Windows APIs.
 * @author freelyflyyy
 */


#pragma once
#include "pch/stdafx.h"
#include "resolver/NtExtResolvers.hpp"
#include "invoker/NtExtInvokers.hpp"

#if defined(_WIN64) || defined(__x86_64__) || defined(__amd64__)
#define _WIN64 1
#elif defined(_M_IX86) || defined(__i386__)
#define _M_IX86 1
#else
#error "Unsupported architecture! Only x86 and x64 are supported."
#endif

namespace NtExt {
}
