#include <ntifs.h>
#include <intrin.h>

extern "C" NTKERNELAPI void RtlPcToFileHeader(PVOID, __int64*);
extern "C" NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS);
extern "C" NTKERNELAPI NTSTATUS NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

bool KdpTrapHook(PKTRAP_FRAME trap_frame, PKEXCEPTION_FRAME exception_frame, PEXCEPTION_RECORD exception_record, PCONTEXT context, __int64, __int64);

decltype(&KdpTrapHook) KdpTrapOriginal = 0;
__int64 g_Backup = 0;

bool CheckProcessName(PEPROCESS process, const char* name)
{
    if (process == 0 || !strstr(PsGetProcessImageFileName(process), name))
    {
        return false;
    }

    return true;
}

HANDLE GetProcessIdByName(PUNICODE_STRING name)
{
	typedef struct _SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		KWAIT_REASON WaitReason;
	} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFO
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER WorkingSetPrivateSize;
		ULONG HardFaultCount;
		ULONG NumberOfThreadsHighWatermark;
		ULONGLONG CycleTime;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR UniqueProcessKey;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
		SYSTEM_THREAD_INFORMATION Threads[1];
	} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

	ULONG size = 0;
	NTSTATUS status = NtQuerySystemInformation(5, 0, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return 0;
	}

	PSYSTEM_PROCESS_INFO info = (PSYSTEM_PROCESS_INFO)ExAllocatePool(NonPagedPool, size);
	if (info == 0)
	{
		return 0;
	}

	status = NtQuerySystemInformation(5, info, size, 0);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(info, 'enoN');
		return 0;
	}

	PSYSTEM_PROCESS_INFO process = info;
	while (process->NextEntryOffset != 0)
	{
		if (RtlEqualUnicodeString(name, &process->ImageName, true))
		{
			HANDLE pid = process->UniqueProcessId;
			ExFreePoolWithTag(info, 'enoN');
			return pid;
		}
		process = (PSYSTEM_PROCESS_INFO)((__int64)process + process->NextEntryOffset);
	}

	ExFreePoolWithTag(info, 'enoN');
	return 0;
}

const __int64 GetSrcOpnd(unsigned __int64 exception_addr, unsigned __int64* regs)
{
    return regs[*(unsigned char*)(exception_addr + 2) & 7];
}

__int64 GetKernelBase()
{
    __int64 base = 0;
    RtlPcToFileHeader(MmGetSystemRoutineAddress, &base);
    return base;
}

void WriteDirBase(PEPROCESS process, __int64 value)
{
    *(__int64*)((__int64)process + 0x28) = value;
}

__int64 ReadDirBase(PEPROCESS process)
{
    return *(__int64*)((__int64)process + 0x28);
}

void HandleCr3(const __int64 opnd, const __int64 origial)
{
    PEPROCESS process = 0;
    if (!_bittest64(&opnd, 62))
    {
        __writecr3(opnd);
        return;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId(PsGetCurrentProcessId(), &process)) && CheckProcessName(process, "cheatengine-x8"))
    {
        __writecr3(ReadDirBase(process));
        ObDereferenceObject(process);
        return;
    }
    else
    {
        __writecr3(origial);
    }
}

bool KdpTrapHook(PKTRAP_FRAME trap_frame, PKEXCEPTION_FRAME exception_frame, PEXCEPTION_RECORD exception_record, PCONTEXT context, __int64 _, __int64 __)
{
    if (*(unsigned __int16*)(exception_record->ExceptionAddress) == 0x220F)
    {
        HandleCr3(GetSrcOpnd(context->Rip, &context->Rax), g_Backup);
        context->Rip += 3;
        return true;
    }

    return KdpTrapOriginal(trap_frame, exception_frame, exception_record, context, _, __);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	// 20H2
    // 0xC50BB4 = KdpDebugRoutineSelect
    // 0x9BBA20 = KdpTrap

    *(unsigned char*)(GetKernelBase() + 0xC50BB4) = 1;

    PEPROCESS process = nullptr;
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"notepad.exe");
    PsLookupProcessByProcessId(GetProcessIdByName(&name), &process);

    _disable();
    g_Backup = ReadDirBase(process);
    WriteDirBase(process, g_Backup | 0x4000000000000000);
    _enable();
    
    // https://github.com/adrianyy/kernelhook
    HkDetourFunction((PVOID)(GetKernelBase() + 0x9BBA20), KdpTrapHook, 18, (PVOID*)&KdpTrapOriginal);
    return STATUS_SUCCESS;
}