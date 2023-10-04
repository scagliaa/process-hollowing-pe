<h1>Process Hollowing PE</h1>

<a>This repository contains a C++ implementation of process hollowing, a technique used to inject code into a target process. The code demonstrates how to create a suspended process, allocate memory in the target process, and write sections from the source to the target process.</a>

<h1>Functions</h1>

The following functions are implemented in the code:

<ul>
  <li><strong>process::get_nt_header</strong>: This function retrieves the NT header from the given DOS header.</li>
  <li><strong>process::is_valid_nt_header</strong>: This function checks if the given NT header is valid.</li>
  <li><strong>process::load_ntdll</strong>: This function loads the ntdll.dll library and returns its handle.</li>
  <li><strong>process::get_nt_query_info_process</strong>: This function retrieves the address of the NtQueryInformationProcess function from the given ntdll.dll handle.</li>
  <li><strong>util::enable_debug_privilege</strong>: This function enables the debug privilege for the current process.</li>
  <li><strong>process::create_suspended_process</strong>: This function creates a suspended process with the given executable path.</li>
  <li><strong>process::allocate_memory_in_target_process</strong>: This function allocates memory in the target process with the given size.</li>
  <li><strong>process::write_process_memory</strong>: This function writes data from the source to the destination in the target process.</li>
  <li><strong>process::get_section_header</strong>: This function retrieves the section header from the given DOS header.</li>
  <li><strong>process::write_sections</strong>: This function writes the sections from the source to the target process.</li>
</ul>

<h1>Usage</h1>
<ul>
<li>Clone the repository.</li>
<li>Open the project in your preferred C++ IDE or compiler.</li>
<li>Place the shellcode in the raw_data variable in <strong>shellcode.h</strong></li>
</ul>
