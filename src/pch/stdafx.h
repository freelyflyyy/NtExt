#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <wtypes.h>

#pragma warning(push)
#pragma warning(disable: 4005) 
#include <ntstatus.h>
#pragma warning(pop)

//Windows version helper
#include <sdkddkver.h>

#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <algorithm>
#include <functional>
#include <cstdarg>