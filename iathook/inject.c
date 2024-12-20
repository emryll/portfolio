#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

#define WHITE 0x7
#define GREEN 0x2
#define RED 0x4
#define PE_SIGNATURE 0x4550

PPEB getPEB() {
    return (PPEB)__readgsqword(0x60);  // For x64
}

void setColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

//* Custom implementation of GetModuleHandleA
PVOID getModuleBase(wchar_t *moduleName) {
    PPEB pPeb = getPEB();
    PEB_LDR_DATA *Ldr = pPeb->Ldr;
    
    PLIST_ENTRY firstFlink = Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY currentFlink = firstFlink;

    LDR_DATA_TABLE_ENTRY *firstEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)firstFlink-0x10); // Flink doesn't point to start of table
    LDR_DATA_TABLE_ENTRY *currentEntry = firstEntry;

    UNICODE_STRING *modName = (UNICODE_STRING *)((ULONG_PTR)firstEntry + 0x58); // BaseDllName

    if (moduleName == NULL) {
        return *(PVOID*)((ULONG_PTR)firstEntry + 0x30); // DllBase
    }

    //? Loop through InMemoryOrderModuleList until you find the correct module
    do {
        if (_wcsicmp(modName->Buffer, moduleName) == 0) {
            return *(PVOID*)((ULONG_PTR)currentEntry + 0x30); // DllBase
        }
        //? move to next one
        currentFlink = currentFlink->Flink;
        currentEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)currentFlink - 0x10);
        modName = (UNICODE_STRING*)((ULONG_PTR)currentEntry + 0x58);
    } while (currentFlink != firstFlink);

    setColor(RED);
    printf("\n[!] Couldn't find module \"%ls\"", moduleName);
    setColor(WHITE);
    return NULL;
}


//* Custom implementation of GetProcAddress
PVOID getFuncAddress(PVOID moduleBase, LPCSTR funcName) {
    //? Parse PE headers located at moduleBase in memory, to get the Export Address Table
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        setColor(RED);
        printf("\n[!] Incorrect PE signature!\n");
        setColor(WHITE);
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportsDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)moduleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!exportsDirectory) {
        setColor(RED);
        printf("\n[!] No export directory found.\n");
        setColor(WHITE);
        return FALSE;
    }    

    DWORD NumberOfNames = exportsDirectory->NumberOfNames;
    PDWORD AddressOfFunctions = (PDWORD)((ULONG_PTR)moduleBase+(ULONG_PTR)exportsDirectory->AddressOfFunctions);
    PDWORD AddressOfNames = (PDWORD)((ULONG_PTR)moduleBase+(ULONG_PTR)exportsDirectory->AddressOfNames);
    PDWORD AddressOfNameOrdinals = (PDWORD)((ULONG_PTR)moduleBase+(ULONG_PTR)exportsDirectory->AddressOfNameOrdinals);

    //? Loop through AddressOfNames until you find funcName (at AddressOfNames[i])
    //? The address of the function can be found at AddressOfFunctions[ordinal], with ordinal at AddressOfNameOrdinals[i]
    for (DWORD i = 0; i < NumberOfNames; i++) {
        char* fName = (char*)((unsigned char*)moduleBase + AddressOfNames[i]);
        if (strcmp(fName, funcName) == 0) {
            //? AddressOf_[n] does not work, have to do it this way
            WORD ordinal = *((WORD*)((ULONG_PTR)AddressOfNameOrdinals + i*sizeof(WORD)));
			DWORD fRVA = *((DWORD*)((ULONG_PTR)AddressOfFunctions + ordinal*sizeof(DWORD)));
            return (PVOID)((ULONG_PTR)moduleBase+fRVA);
        }
    }
    return NULL;
}

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
    int pid = atoi(argv[1]);
    printf("pid: %d", pid);
    BOOL ok = InjectDLL(pid, L"D:\\koodi\\portfolio\\iathook\\payload.dll");
    if (!ok) {
        printf("\n[!] Failed to inject dll");
        return -1;
    }
    printf("[+] Injected DLL");
    return 1;
}