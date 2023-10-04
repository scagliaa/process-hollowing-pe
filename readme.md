Process Hollowing PE
This repository contains a C++ implementation of process hollowing, a technique used to inject code into a target process. The code demonstrates how to create a suspended process, allocate memory in the target process, and write sections from the source to the target process.
Functions
The following functions are implemented in the code:
process::get_nt_header: This function retrieves the NT header from the given DOS header.
process::is_valid_nt_header: This function checks if the given NT header is valid.
process::load_ntdll: This function loads the ntdll.dll library and returns its handle.
process::get_nt_query_info_process: This function retrieves the address of the NtQueryInformationProcess function from the given ntdll.dll handle.
util::enable_debug_privilege: This function enables the debug privilege for the current process.
process::create_suspended_process: This function creates a suspended process with the given executable path.
process::allocate_memory_in_target_process: This function allocates memory in the target process with the given size.
process::write_process_memory: This function writes data from the source to the destination in the target process.
process::get_section_header: This function retrieves the section header from the given DOS header.
process::write_sections: This function writes the sections from the source to the target process.
Usage
Clone the repository.
Open the project in your preferred C++ IDE or compiler.
Build and run the project.
Please note that this code is for educational purposes only and should not be used for malicious activities.