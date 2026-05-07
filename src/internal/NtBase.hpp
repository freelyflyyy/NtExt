#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // WIN32_LEAN_AND_MEAN

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <wtypes.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)

// Windows version helper
#include <sdkddkver.h>
