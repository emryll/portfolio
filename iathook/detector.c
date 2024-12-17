#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <stdio.h>

#define WHITE 0x7
#define GREEN 0x2
#define RED 0x4
#define PE_SIGNATURE 0x4550
#define MAX_ENTRIES 3000

typedef struct FN_ENTRY {
    PVOID Address;
    char Name[256];
    char ExportedBy[256];
} FN_ENTRY;

typedef struct FN_ADDRESSES {
    DWORD Count;
    FN_ENTRY Entries[MAX_ENTRIES];
} FN_ADDRESSES;

typedef struct RESULTS {
    BOOL Hooked;
    FN_ADDRESSES HookedList;
} RESULTS;

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

BOOL getModuleIATAddresses(PVOID moduleBase, FN_ADDRESSES* IATList) {
    //? Parse PE headers located at moduleBase in memory, to get the Export Address Table
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        setColor(RED);
        printf("\n[!] Incorrect PE signature!\n");
        setColor(WHITE);
        return FALSE;
    }
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)moduleBase);
	LPCSTR libraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    
    while (importDescriptor->Name != 0) {
		libraryName = (LPCSTR)((DWORD_PTR)importDescriptor->Name + (DWORD_PTR)moduleBase);
        if (strcmp(libraryName, "") == 0) {
            break;
        }
        //if (strncmp(libraryName, "api-ms-win", strlen("api-ms-win")) == 0) {
        //    continue;
        //}
        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
    // actually, IMAGE_IMPORT_BY_NAME.Hint contains the function's index in EAT,
    // which could be used for quite a bit quicker lookup, but I'm not doing that here
        while (originalFirstThunk->u1.AddressOfData != 0) {
            if (originalFirstThunk == NULL || firstThunk == NULL) {
                printf("[!] NULL pointer\n");
            }
            //if (((uintptr_t)firstThunk) % sizeof(void*) != 0) {
            //    printf("[!] Misaligned pointer at entry %d\n", IATList->Count);
            //    continue;
            //}
            if (firstThunk->u1.Function == 0) {
                continue;
            }
            //? kernelbase is getting here
            if (IATList->Count == MAX_ENTRIES) {
                printf("[i] Function limit reached...\n");
                break;
            }
            printf("[i] originalFirstThunk: %#x, firstThunk: %#x\n", originalFirstThunk, firstThunk);
            printf("[i] AddressOfData alignment: %d\n", ((uintptr_t)originalFirstThunk->u1.AddressOfData) % sizeof(void*));
            printf("[i] firstThunk alignment: %d\n", ((uintptr_t)firstThunk) % sizeof(void*));
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);
            printf("%s", functionName->Name);
            IATList->Entries[IATList->Count].Address = (PVOID)firstThunk->u1.Function;
            strcpy(IATList->Entries[IATList->Count].Name, functionName->Name);
            strcpy(IATList->Entries[IATList->Count].ExportedBy, libraryName);
            printf("[i] %s!%s: %#x  , %d\n", IATList->Entries[IATList->Count].ExportedBy, IATList->Entries[IATList->Count].Name, IATList->Entries[IATList->Count].Address, IATList->Count);
            IATList->Count++;
            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return TRUE;
}

//? I kept getting false positives on these functions so I'm ignoring them
BOOL criticalFunction(LPCSTR fName) {
    if (strcmp(fName, "DeleteCriticalSection") == 0 || strcmp(fName, "EnterCriticalSection") == 0) {
        return TRUE;
    }
    if (strcmp(fName, "InitializeCriticalSection") == 0 || strcmp(fName, "LeaveCriticalSection") == 0) {
        return TRUE;
    }
    return FALSE;
}

void compareAddresses(FN_ADDRESSES* IATList, RESULTS* results) {
    int failedCount = 0;
    printf("[i] iat count: %d\n", IATList->Count);
    for (DWORD i = 0; i < IATList->Count; i++) {
        if (strncmp(IATList->Entries[i].ExportedBy, "api-ms-win", strlen("api-ms-win")) == 0) {
            continue;
        }
        size_t len = mbstowcs(NULL, IATList->Entries[i].ExportedBy, 0);  // Get the required size
        if (len == (size_t)-1) {
            printf("\n[!] mbstowcs failed\n");
            continue;
        }

        wchar_t* wideStr = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
        if (wideStr == NULL) {
            printf("\n[!] malloc failed\n");
            continue;
        }
        mbstowcs(wideStr, IATList->Entries[i].ExportedBy, len + 1);

        PVOID moduleBase = getModuleBase(wideStr);
        if (moduleBase == NULL) {
            failedCount++;
            continue;
        }
        free(wideStr);

        PVOID EATAddress = getFuncAddress(moduleBase, IATList->Entries[i].Name);
        if (EATAddress == NULL) {
            printf("\n[!] Failed to get EAT address for %s\n\n", IATList->Entries[i].Name);
            failedCount++;
            continue;
        }

        if (EATAddress != IATList->Entries[i].Address) {
            if (criticalFunction(IATList->Entries[i].Name)) {
                continue;
            }
            setColor(RED);
            printf("\n\t[!] IAT-EAT mismatch found on %s!%s\n\t\t\\==={ Address in IAT: %#x\n\t\t \\=={ Address in EAT: %#x\n\n", IATList->Entries[i].ExportedBy, IATList->Entries[i].Name, IATList->Entries[i].Address, EATAddress);
            setColor(WHITE);
            //? Update results
            if (results->Hooked == FALSE) { results->Hooked = TRUE; }
            if (results->HookedList.Count == MAX_ENTRIES) {
                printf("[i] results max function limit reached...\n");
                return;
            }
                results->HookedList.Entries[results->HookedList.Count].Address = IATList->Entries[i].Address;
                strncpy(results->HookedList.Entries[results->HookedList.Count].Name, IATList->Entries[i].Name, 255);
                strncpy(results->HookedList.Entries[results->HookedList.Count].ExportedBy, IATList->Entries[i].ExportedBy, 255);
                results->HookedList.Count++;
        } else {
            setColor(GREEN);
            printf("\t[+] %s!%s addresses match\n", IATList->Entries[i].ExportedBy, IATList->Entries[i].Name);
            setColor(WHITE);
        }
    }
    printf("\n[i] %d/%d failed on error\n", failedCount, IATList->Count);
}

void isHooked(RESULTS* results) {
    //? PEB walk to reach modules list
    PPEB pPeb = getPEB();
    PEB_LDR_DATA *Ldr = pPeb->Ldr;

    PLIST_ENTRY firstFlink = Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY currentFlink = firstFlink;

    LDR_DATA_TABLE_ENTRY *firstEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)firstFlink-0x10); // Flink doesn't point to start of table
    LDR_DATA_TABLE_ENTRY *currentEntry = firstEntry;

    //? Loop for each module, here you get the IAT, then you need to loop through it and compare addresses to EAT
    do {
        UNICODE_STRING *modName = (UNICODE_STRING *)((ULONG_PTR)currentEntry + 0x58); // BaseDllName
  /*      if (wcsicmp(modName->Buffer, L"kernelbase.dll") == 0) {
            printf("[i] kernelbase, skipping...\n");
        currentFlink = currentFlink->Flink;
        currentEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)currentFlink - 0x10);
            continue;
        }*/
        printf("\n====================[ %ls ]========================\n", modName->Buffer);
        PVOID imageBase = getModuleBase(modName->Buffer);
        if (imageBase == NULL) {
            printf("\n[!] Failed to get image base address of %ls\n", modName->Buffer);
            continue;
        }
        FN_ADDRESSES* IATEntries = (FN_ADDRESSES*)malloc(sizeof(FN_ADDRESSES));
        if (IATEntries == NULL) {
            printf("\n[!] malloc failed\n");
        }
        IATEntries->Count = 0;
        getModuleIATAddresses(imageBase, IATEntries);
        if (IATEntries->Count == 0) {
            printf("\n[!] Couldn't find IAT entries for %ls\n", modName->Buffer);
            currentFlink = currentFlink->Flink;
            currentEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)currentFlink - 0x10);
            free(IATEntries);
            continue;
        }
        printf("[i] Retrieved %d functions from IAT\n", IATEntries->Count);

        // compare iat to eat, fill results
        compareAddresses(IATEntries, results);
        free(IATEntries);

        //? move to next one
        currentFlink = currentFlink->Flink;
        currentEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)currentFlink - 0x10);
    } while (currentFlink != firstFlink);
}

int main() {
    //* parse cmdline arguments and flags
    // -s for silent
    // -dll=[dll] to specify only certain dll to check, null for the main module
    RESULTS* results = (RESULTS*)malloc(sizeof(RESULTS));
    results->HookedList.Count = 0;
    isHooked(results);
    if (results->Hooked) {
        printf("[!] Process IAT(s) is hooked\n");
    } else {
        printf("[+] Process IATs are not hooked\n");
    }
    free(results);
}