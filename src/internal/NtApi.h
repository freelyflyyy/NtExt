#pragma once
#include "../pch/stdafx.h"

/**
 * @brief Template definitions for Windows kernel structures
 *        (PEB, TEB, UNICODE/ANSI STRING) compatible with both
 *        32-bit and 64-bit builds.
 * @author freelyfly
 *
 * @details
 * This header provides templated representations of common Windows
 * internal structures to facilitate cross-architecture code reuse.
 * Pay attention to alignment, platform-specific fields, and calling
 * conventions when instantiating these templates for a target build.
 */

namespace NtExt {
    // NOLINTNEXTLINE
    typedef enum _MEMORY_INFORMATION_CLASS {
        MemoryBasicInformation = 0,
        MemoryWorkingSetInformation = 1,
        MemoryMappedFilenameInformation = 2,
        MemoryRegionInformation = 3,
        MemoryWorkingSetExInformation = 4,
        MemorySharedCommitInformation = 5,
        MemoryImageInformation = 6,
        MemoryRegionInformationEx = 7,
        MemoryPrivilegedBasicInformation = 8
    } MEMORY_INFORMATION_CLASS;

    template <typename T>
    // NOLINTNEXTLINE
    struct _PROCESS_BASIC_INFORMATION_T {
        NTSTATUS ExitStatus;
        UINT32 Reserved0;
        T PebBaseAddress;
        T AffinityMask;
        LONG BasePriority;
        ULONG Reserved1;
        T uUniqueProcessId;
        T uInheritedFromUniqueProcessId;
    };

    typedef _PROCESS_BASIC_INFORMATION_T<DWORD> PROCESS_BASIC_INFORMATION32;
    typedef _PROCESS_BASIC_INFORMATION_T<DWORD64> PROCESS_BASIC_INFORMATION64;

    template <class T>
    // NOLINTNEXTLINE
    struct _LIST_ENTRY_T {
        T Flink;
        T Blink;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _STRING_T {
        union {
            struct {
                WORD Length;
                WORD MaximumLength;
            };

            T dummy;
        };

        T Buffer;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _NT_TIB_T {
        T ExceptionList;
        T StackBase;
        T StackLimit;
        T SubSystemTib;
        T FiberData;
        T ArbitraryUserPointer;
        T Self;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _CLIENT_ID_T {
        T UniqueProcess;
        T UniqueThread;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _TEB_T_ {
        _NT_TIB_T<T> NtTib;
        T EnvironmentPointer;
        _CLIENT_ID_T<T> ClientId;
        T ActiveRpcHandle;
        T ThreadLocalStoragePointer;
        T ProcessEnvironmentBlock;
        DWORD LastErrorValue;
        DWORD CountOfOwnedCriticalSections;
        T CsrClientThread;
        T Win32ThreadInfo;
        DWORD User32Reserved[26];
        //rest of the structure is not defined for now, as it is not needed
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _LDR_DATA_TABLE_ENTRY_T {
        _LIST_ENTRY_T<T> InLoadOrderLinks;
        _LIST_ENTRY_T<T> InMemoryOrderLinks;
        _LIST_ENTRY_T<T> InInitializationOrderLinks;
        T DllBase;
        T EntryPoint;

        union {
            DWORD SizeOfImage;
            T dummy01;
        };

        _STRING_T<T> FullDllName;
        _STRING_T<T> BaseDllName;
        DWORD Flags;
        WORD LoadCount;
        WORD TlsIndex;

        union {
            _LIST_ENTRY_T<T> HashLinks;

            struct {
                T SectionPointer;
                T CheckSum;
            };
        };

        union {
            T LoadedImports;
            DWORD TimeDateStamp;
        };

        T EntryPointActivationContext;
        T PatchInformation;
        _LIST_ENTRY_T<T> ForwarderLinks;
        _LIST_ENTRY_T<T> ServiceTagLinks;
        _LIST_ENTRY_T<T> StaticLinks;
        T ContextInformation;
        T OriginalBase;
        _LARGE_INTEGER LoadTime;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _PEB_LDR_DATA_T {
        DWORD Length;
        DWORD Initialized;
        T SsHandle;
        _LIST_ENTRY_T<T> InLoadOrderModuleList;
        _LIST_ENTRY_T<T> InMemoryOrderModuleList;
        _LIST_ENTRY_T<T> InInitializationOrderModuleList;
        T EntryInProgress;
        DWORD ShutdownInProgress;
        T ShutdownThreadId;
    };

    template <class T, class NGF, int A>
    // NOLINTNEXTLINE
    struct _PEB_T {
        union {
            struct {
                BYTE InheritedAddressSpace;
                BYTE ReadImageFileExecOptions;
                BYTE BeingDebugged;
                BYTE BitField;
            };

            T dummy01;
        };

        T Mutant;
        T ImageBaseAddress;
        T Ldr;
        T ProcessParameters;
        T SubSystemData;
        T ProcessHeap;
        T FastPebLock;
        T AtlThunkSListPtr;
        T IFEOKey;
        T CrossProcessFlags;
        T UserSharedInfoPtr;
        DWORD SystemReserved;
        DWORD AtlThunkSListPtr32;
        T ApiSetMap;
        T TlsExpansionCounter;
        T TlsBitmap;
        DWORD TlsBitmapBits[2];
        T ReadOnlySharedMemoryBase;
        T HotpatchInformation;
        T ReadOnlyStaticServerData;
        T AnsiCodePageData;
        T OemCodePageData;
        T UnicodeCaseTableData;
        DWORD NumberOfProcessors;

        union {
            DWORD NtGlobalFlag;
            NGF dummy02;
        };

        LARGE_INTEGER CriticalSectionTimeout;
        T HeapSegmentReserve;
        T HeapSegmentCommit;
        T HeapDeCommitTotalFreeThreshold;
        T HeapDeCommitFreeBlockThreshold;
        DWORD NumberOfHeaps;
        DWORD MaximumNumberOfHeaps;
        T ProcessHeaps;
        T GdiSharedHandleTable;
        T ProcessStarterHelper;
        T GdiDCAttributeList;
        T LoaderLock;
        DWORD OSMajorVersion;
        DWORD OSMinorVersion;
        WORD OSBuildNumber;
        WORD OSCSDVersion;
        DWORD OSPlatformId;
        DWORD ImageSubsystem;
        DWORD ImageSubsystemMajorVersion;
        T ImageSubsystemMinorVersion;
        T ActiveProcessAffinityMask;
        T GdiHandleBuffer[A];
        T PostProcessInitRoutine;
        T TlsExpansionBitmap;
        DWORD TlsExpansionBitmapBits[32];
        T SessionId;
        ULARGE_INTEGER AppCompatFlags;
        ULARGE_INTEGER AppCompatFlagsUser;
        T pShimData;
        T AppCompatInfo;
        _STRING_T<T> CSDVersion;
        T ActivationContextData;
        T ProcessAssemblyStorageMap;
        T SystemDefaultActivationContextData;
        T SystemAssemblyStorageMap;
        T MinimumStackCommit;
        T FlsCallback;
        _LIST_ENTRY_T<T> FlsListHead;
        T FlsBitmap;
        DWORD FlsBitmapBits[4];
        T FlsHighIndex;
        T WerRegistrationData;
        T WerShipAssertPtr;
        T pContextData;
        T pImageHeaderHash;
        T TracingFlags;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _CURDIR_T {
        _STRING_T<T> DosPath;
        T Handle;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _RTL_DRIVE_LETTER_CURDIR_T {
        WORD Flags;
        WORD Length;
        ULONG TimeStamp;
        _STRING_T<T> DosPath;
    };

    template <class T>
    // NOLINTNEXTLINE
    struct _RTL_USER_PROCESS_PARAMETERS_T {
        ULONG MaximumLength;
        ULONG Length;
        ULONG Flags;
        ULONG DebugFlags;
        T ConsoleHandle;
        ULONG ConsoleFlags;
        T StandardInput;
        T StandardOutput;
        T StandardError;
        _CURDIR_T<T> CurrentDirectory;
        _STRING_T<T> DllPath;
        _STRING_T<T> ImagePathName;
        _STRING_T<T> CommandLine;
        T Environment;
        ULONG StartingX;
        ULONG StartingY;
        ULONG CountX;
        ULONG CountY;
        ULONG CountCharsX;
        ULONG CountCharsY;
        ULONG FillAttribute;
        ULONG WindowFlags;
        ULONG ShowWindowFlags;
        _STRING_T<T> WindowTitle;
        _STRING_T<T> DesktopInfo;
        _STRING_T<T> ShellInfo;
        _STRING_T<T> RuntimeData;
        _RTL_DRIVE_LETTER_CURDIR_T<T> CurrentDirectories[32];
        T EnvironmentSize;
        T EnvironmentVersion;
        T PackageDependencyData;
        ULONG ProcessGroupId;
        ULONG LoaderThreads;
        _STRING_T<T> RedirectionDllName;
        _STRING_T<T> HeapPartitionName;
        T DefaultThreadpoolCpuSetMasks;
        ULONG DefaultThreadpoolCpuSetMaskCount;
        ULONG DefaultThreadpoolThreadMaximum;
    };


    typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
    typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;

    typedef _TEB_T_<DWORD> TEB32;
    typedef _TEB_T_<DWORD64> TEB64;

    typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
    typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

    typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
    typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

    typedef _STRING_T<DWORD> UNICODE_STRING32;
    typedef _STRING_T<DWORD64> UNICODE_STRING64;
    typedef UNICODE_STRING32* PUNICODE_STRING32;
    typedef UNICODE_STRING64* PUNICODE_STRING64;


    typedef _STRING_T<DWORD> ANSI_STRING32;
    typedef _STRING_T<DWORD64> ANSI_STRING64;
    typedef ANSI_STRING32* PANSI_STRING32;
    typedef ANSI_STRING64* PANSI_STRING64;

    typedef _RTL_USER_PROCESS_PARAMETERS_T<ULONG> RTL_USER_PROCESS_PARAMETERS32;
    typedef _RTL_USER_PROCESS_PARAMETERS_T<ULONGLONG> RTL_USER_PROCESS_PARAMETERS64;
}
