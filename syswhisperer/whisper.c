#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_ENTRIES 500
#define WHITE 0x7
#define GREEN 0x2
#define RED 0x4
#define AQUA 0x3
#define PE_SIGNATURE 0x4550

typedef struct ZW_ENTRY {
    char Name[256];
    PVOID Address;
} ZW_ENTRY;

typedef struct ZW_LIST {
    DWORD Count;
    ZW_ENTRY Entries[MAX_ENTRIES];
} ZW_LIST;

typedef struct SYSCALL_INFO {
    DWORD64 dwSsn; // SSN
    PVOID pAddress; // function address in ntdll
    char Name[256];//DWORD64 dwHash; // hashed function name
} SYSCALL_INFO;

typedef struct SYSCALL_LIST {
    DWORD64 Count;
    SYSCALL_INFO Entries[MAX_ENTRIES];
} SYSCALL_LIST;


void setColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

int compareAddress(const void* a, const void* b) {
    const ZW_ENTRY* entryA = (const ZW_ENTRY*)a;
    const ZW_ENTRY* entryB = (const ZW_ENTRY*)b;

    // Compare the addresses
    if (entryA->Address < entryB->Address) {
        return -1;
    } else if (entryA->Address > entryB->Address) {
        return 1;
    }
    return 0;
}

void sortListByAddress(ZW_LIST* list) {
    if (list == NULL || list->Entries == NULL || list->Count < 2) {
        printf("\n[!] Couldn't sort list, not enough entries\n\t\\==={ Count: %d\n", list->Count);
        return;  // Nothing to sort
    }
    // Call qsort with the comparison function
    qsort(list->Entries, list->Count, sizeof(ZW_ENTRY), compareAddress);
}

PPEB getPEB() {
    return (PPEB)__readgsqword(0x60);
}

PVOID getModuleBase(wchar_t *moduleName) {
    PPEB pPeb = getPEB();
    PEB_LDR_DATA *Ldr = pPeb->Ldr;
    
    PLIST_ENTRY firstFlink = Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY currentFlink = firstFlink;

    LDR_DATA_TABLE_ENTRY *firstEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)firstFlink-0x10); // Flink doesn't point to start of table
    LDR_DATA_TABLE_ENTRY *currentEntry = firstEntry;

    UNICODE_STRING *modName = (UNICODE_STRING *)((ULONG_PTR)firstEntry + 0x58); // BaseDllName

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

BOOL isSyscall(const uint8_t* address) {
    return address[0] == 0x0F && address[1] == 0x05;
}

PVOID scanForSyscall(const uint8_t* startAddress) {
    for (int i = 0; i < 500; i++) {
        if (isSyscall(startAddress+i)) {
            setColor(GREEN);
            printf("[+] Syscall found!\n\t\\==={ Address: %#X\n", startAddress+i);
            setColor(WHITE);
            return (PVOID)startAddress+i;
        }
    }
    printf("\n[!] No syscall found!\n");
    return NULL;
}


BOOL whisper(SYSCALL_LIST* syscallList, PVOID* syscallVA, int* count) {
    //? this parsing can be sigged, probably bypassable with some math with extra steps for the offsets
    //* walk peb to get ntdll imagebase
    PVOID ntBase = getModuleBase(L"ntdll.dll"); //TODO: Use hash instead of name
    setColor(GREEN);
    printf("[+] Got ntdll image base: %#X\n", ntBase);
    setColor(WHITE);

    //? Parse PE headers located at moduleBase in memory, to get the Export Address Table
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)ntBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ntBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        setColor(RED);
        printf("\n[!] Incorrect PE signature!\n");
        setColor(WHITE);
        return FALSE;
    }
    printf("[i] PE file signature: %#X\n", ntHeaders->Signature);

    PIMAGE_EXPORT_DIRECTORY exportsDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ntBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!exportsDirectory) {
        setColor(RED);
        printf("\n[!] No export directory found.\n");
        setColor(WHITE);
        return FALSE;
    }    

    //* loop through AddressOfNames until you find a zw function
    //* RVA is AddressOfFunctions[AddressOfOrdinals[index]]
    //* save name and address
    DWORD NumberOfNames = exportsDirectory->NumberOfNames;
    PDWORD AddressOfFunctions = (PDWORD)((ULONG_PTR)ntBase+(ULONG_PTR)exportsDirectory->AddressOfFunctions);
    PDWORD AddressOfNames = (PDWORD)((ULONG_PTR)ntBase+(ULONG_PTR)exportsDirectory->AddressOfNames);
    PDWORD AddressOfNameOrdinals = (PDWORD)((ULONG_PTR)ntBase+(ULONG_PTR)exportsDirectory->AddressOfNameOrdinals);

    ZW_LIST ZwFuncs;
    ZwFuncs.Count = 0;

    for (DWORD i = 0; i < NumberOfNames; i++) {
        if (ZwFuncs.Count >= MAX_ENTRIES) {
            printf("[!] Exceeded maximum number of entries (%d). Aborting.\n", MAX_ENTRIES);
            break;
        }
        char* fName = (char*)((unsigned char*)ntBase + AddressOfNames[i]);
        if (fName[0] == 'Z' && fName[1] == 'w') {
            //? AddressOf_[n] does not work, have to do it this way
            WORD ordinal = *((WORD*)((ULONG_PTR)AddressOfNameOrdinals + i*sizeof(WORD)));
			DWORD fRVA = *((DWORD*)((ULONG_PTR)AddressOfFunctions + ordinal*sizeof(DWORD)));
            strcpy(ZwFuncs.Entries[ZwFuncs.Count].Name, fName);
            ZwFuncs.Entries[ZwFuncs.Count].Address = (PVOID)((ULONG_PTR)ntBase+fRVA);
            ZwFuncs.Count++;
        }
    }

    setColor(GREEN);
    printf("\n[+] Found %d Zw functions!\n", ZwFuncs.Count);
    setColor(WHITE);
    *count = ZwFuncs.Count;

    //? The whole idea behind FreshyCalls and SysWhispers2 is that
    //? since syscall IDs are following each other incrementally,
    //? you can deduce SSN from address!

    //* sort function addresses and now index is SSN
    sortListByAddress(&ZwFuncs);

    //* loop through sorted addresses and fill SYSCALL_LIST with SSN (index),
    //* hash and function address
    for (DWORD i = 0; i < ZwFuncs.Count; i++) {
        syscallList->Entries[i].dwSsn = i;
        syscallList->Entries[i].pAddress = ZwFuncs.Entries[i].Address;
        strcpy(syscallList->Entries[i].Name, ZwFuncs.Entries[i].Name);
    }
    syscallList->Count = ZwFuncs.Count;

    //? now we still do need find A syscall instruction inside ntdll
    *syscallVA = scanForSyscall(ZwFuncs.Entries[0].Address);
    if (syscallVA == NULL) {
        printf("\n[!] Couldn't find syscall in ntdll\n");
        return FALSE;
    }
    return TRUE;
}

int main() {
    SYSCALL_LIST syscallList; //? list of syscalls
    PVOID syscallVA; //? virtual address (not relative) of a syscall instruction in ntdll
    int count = 0;  //? the amount of functions in syscallList
    BOOL ok = whisper(&syscallList, &syscallVA, &count);
    if (!ok) {
        setColor(RED);
        printf("\n[!] Whisper failed!\n");
        setColor(WHITE);
    } else {
        setColor(AQUA);
        printf("\n\n+==================================================================================+\n");
        printf("|  %-54s %-10s    %-9s  |\n+==================================================================================+\n", "Function name", "SSN", "Address");
        for (int i = 0; i < count; i++) {
            printf("| %-55s 0x%-10x 0x%-9x |\n",
                syscallList.Entries[i].Name, syscallList.Entries[i].dwSsn, syscallList.Entries[i].pAddress);
        }
        printf("+==================================================================================+\n");
        setColor(WHITE);
    }
    return 1;
}