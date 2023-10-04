#include <winternl.h>

typedef NTSTATUS(WINAPI* NTQUERYINFOPROC)(
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
);

    // SHELLCODE
unsigned char raw_data[0] = {};