#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

DWORD get_process_pid_by_name(const char *process_name)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (strcmp(entry.szExeFile, process_name) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

bool inject_dll(DWORD pid, const char *dll_name)
{
    HANDLE handle = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );

    if (!handle) {
        return false;
    }

    LPVOID remote_memory = VirtualAllocEx(handle,nullptr, strlen(dll_name) + 1,
                                          MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

    WriteProcessMemory(handle, remote_memory, dll_name, strlen(dll_name) + 1,
        nullptr);

    LPTHREAD_START_ROUTINE start_address = (LPTHREAD_START_ROUTINE) GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );

    CreateRemoteThread(handle,nullptr, 0, start_address, remote_memory,
                       0,nullptr
    );

    CloseHandle(handle);
    return true;
}

int main()
{
    char process_name[32];
    char dll_name[32];

    printf("Enter the process name: ");
    scanf("%31s", process_name);

    DWORD pid = get_process_pid_by_name(process_name);

    if (!pid) {
        for (; pid == 0; pid = get_process_pid_by_name(process_name)) {
            Sleep(1000);
            puts("Waiting for process creation...");
        }
    }

    printf("Enter the dll name: ");
    scanf("%31s", dll_name);

    if (inject_dll(pid, dll_name)) {
        printf("Injected DLL %s!\n", dll_name);
    }

    return 0;
}
