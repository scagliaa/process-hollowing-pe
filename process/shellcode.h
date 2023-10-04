#include <filesystem>
#include <iostream>
#include <ntstatus.h>
#include <optional>
#include <windows.h>
#include <winternl.h>

// Define the function types
typedef NTSTATUS(NTAPI *NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef BOOL(WINAPI *CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef LPVOID(WINAPI *VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

// SHELLCODE
unsigned char raw_bytes[0] = {};