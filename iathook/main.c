#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define WHITE 0x7
#define GREEN 0x2
#define RED 0x4
#define PE_SIGNATURE 0x4550
#define MAX_ENTRIES 1000

typedef struct ENTRY {
    char Name[256];
    PVOID HookedAddress;
} ENTRY;

typedef struct RESULTS {
    BOOL Hooked;
    DWORD Count;
    ENTRY Entries[MAX_ENTRIES]
} RESULTS;

//? Simple DLL injection into specified process. Resolves HANDLE from process ID
BOOL InjectDLL(int pid, PWCHAR dllName) {
    LPVOID pLibAddr;
    SIZE_T szWrittenBytes;
    HANDLE hThread;    

    //? Get address of LoadLibrary function
    //? KnownDLLs (like kernel32.dll) have the same address across processes, for memory efficiency.
    //? You can confirm this fact with Process Hacker or a similar tool. (look at DLL addresses)
    PVOID k32Base = getModuleBase(L"kernel32.dll");
    setColor(GREEN);
    printf("[+] Got kernel32.dll base: %#X\n", k32Base);
    setColor(WHITE);
    PVOID pLoadLibrary = getFuncAddress(k32Base, "LoadLibraryW");
    if (pLoadLibrary == NULL) {
        setColor(RED);
        printf("\n[!] Failed to get LoadLibrary address\n");
        setColor(WHITE);
        return FALSE;
    }
    setColor(GREEN);
    printf("[+] Got LoadLibrary address: %#X\n", pLoadLibrary);
    setColor(WHITE);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        setColor(RED);
        printf("\n[!] Failed to open process, error code: %#X\n", GetLastError());
        setColor(WHITE);
        return FALSE;
    }
    //? Allocate memory into the target process for DLL name
    pLibAddr = VirtualAllocEx(hProcess, NULL, (wcslen(dllName)+1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pLibAddr == NULL) {
        setColor(RED);
        printf("\n[!] VirtualAllocEX failed: %d\n", GetLastError());
        setColor(WHITE);
        return FALSE;
    }
    
    //? Write DLL name into the target processes memory space
    if (!WriteProcessMemory(hProcess, pLibAddr, dllName, (wcslen(dllName)+1) * sizeof(WCHAR), &szWrittenBytes)) {
        setColor(RED);
        printf("\n[!] WriteProcessMemory failed: %d\n", GetLastError());
        setColor(WHITE);
        return FALSE;
    }
    printf("[i] Wrote %d bytes to remote process\n",  szWrittenBytes);
    
    //? Create a thread in the remote process, in order to load the DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pLibAddr, 0, NULL);
    if (hThread == NULL) {
        setColor(RED);
        printf("\n[!] CreateRemoteThread failed: %d\n", GetLastError());
        setColor(WHITE);
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char** argv) {
    HANDLE hEvent;
    int pid = argv[1];

    //* setup sharedmem and open event 
    // CreateFileMapping, sizeof(RESULTS)
    // MapViewOfFile(full file mapping)

    BOOL ok = InjectDLL(pid, L"detector.dll");
    if (!ok) {
        setColor(RED);
        printf("\n[!] DLL injection failed\n");
        setColor(WHITE);
    }
    
    hEvent = OpenEvent();
    WaitForSingleObject(hEvent);
    //* Read shared memory RESULTS
    
    //* Print results

    return 1;
}