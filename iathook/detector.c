#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <stdio.h>
#include "detector.h"

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

BOOL getModuleIATAddresses(PVOID moduleBase, FN_ADDRESSES* IATList, UNICODE_STRING* modName) {
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
    
        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
    // actually, IMAGE_IMPORT_BY_NAME.Hint contains the function's index in EAT,
    // which could be used for quite a bit quicker lookup, but I'm not doing that here
        while (originalFirstThunk->u1.AddressOfData != 0) {
            if (originalFirstThunk == NULL || firstThunk == NULL) {
                printf("[!] NULL pointer\n");
            }
            
            if (firstThunk->u1.Function == 0) {
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
            //? kernelbase is getting here
            if (IATList->Count == MAX_ENTRIES-1) {
                printf("[i] Function limit reached...\n");
                break;
            }
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);
            if ((SIZE_T)functionName & 0xff00000000000000) {
                //printf("[*] Skipping proxied import\n");
                originalFirstThunk++;
                firstThunk++;
                continue;
            }

            if (firstThunk->u1.Function == 0) {
                printf("[i] Skipping null function entry\n");
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
            //printf("%s", functionName->Name);
            IATList->Entries[IATList->Count].Address = (PVOID)firstThunk->u1.Function;
            strncpy(IATList->Entries[IATList->Count].Name, functionName->Name, 255);
            strcpy(IATList->Entries[IATList->Count].ExportedBy, libraryName);
            //printf("[i] %s!%s: %#x  , %d\n", IATList->Entries[IATList->Count].ExportedBy, IATList->Entries[IATList->Count].Name, IATList->Entries[IATList->Count].Address, IATList->Count);
            IATList->Count++;
            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return TRUE;
}

void compareAddresses(FN_ADDRESSES* IATList, RESULTS* results) {
    int failedCount = 0;
    for (DWORD i = 0; i < IATList->Count; i++) {
        if (strncmp(IATList->Entries[i].ExportedBy, "api-ms-win", strlen("api-ms-win")) == 0) {
            continue;
        }
        
        HMODULE moduleBase = GetModuleHandleA(IATList->Entries[i].ExportedBy);
        if (moduleBase == NULL) {
            failedCount++;
            continue;
        }

        //PVOID EATAddress = getFuncAddress(moduleBase, IATList->Entries[i].Name);
        PVOID EATAddress = GetProcAddress(moduleBase, IATList->Entries[i].Name);
        if (EATAddress == NULL) {
            printf("\n[!] Failed to get EAT address for %s\n\n", IATList->Entries[i].Name);
            failedCount++;
            continue;
        }

        if (EATAddress != IATList->Entries[i].Address) {
            //if (criticalFunction(IATList->Entries[i].Name)) {
            //    continue;
            //}
            //setColor(RED);
            //printf("\n\t[!] IAT-EAT mismatch found on %s!%s\n\t\t\\==={ Address in IAT: %#x\n\t\t \\=={ Address in EAT: %#x\n\n", IATList->Entries[i].ExportedBy, IATList->Entries[i].Name, IATList->Entries[i].Address, EATAddress);
            //setColor(WHITE);
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
            //setColor(GREEN);
            //printf("\t[+] %s!%s addresses match\n", IATList->Entries[i].ExportedBy, IATList->Entries[i].Name);
            //setColor(WHITE);
        }
    }
    //printf("\n[i] %d/%d failed on error\n", failedCount, IATList->Count);
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
        
        //printf("\n====================[ %ls ]========================\n", modName->Buffer);
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
        getModuleIATAddresses(imageBase, IATEntries, modName);
        if (IATEntries->Count == 0) {
            //printf("\n[!] Couldn't find IAT entries for %ls\n", modName->Buffer);
            currentFlink = currentFlink->Flink;
            currentEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)currentFlink - 0x10);
            free(IATEntries);
            continue;
        }
        //printf("[i] Retrieved %d functions from IAT\n", IATEntries->Count);

        // compare iat to eat, fill results
        compareAddresses(IATEntries, results);
        free(IATEntries);

        //? move to next one
        currentFlink = currentFlink->Flink;
        currentEntry = (LDR_DATA_TABLE_ENTRY*)((ULONG_PTR)currentFlink - 0x10);
    } while (currentFlink != firstFlink);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, "Global\\detector");
        if (hEvent != NULL) {
        //MessageBox(NULL, "DLL loaded", "DllMain", MB_OK);
            HANDLE hSharedMem = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, "detector");
            if (hSharedMem != NULL) {
                // map shared mem to this process' memory space
                RESULTS* sharedResults = (RESULTS*)MapViewOfFile(
                    hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(RESULTS));
                if (sharedResults != NULL) {
                    // fills results to shared mem
                    isHooked(sharedResults);
                    SetEvent(hEvent);
                    CloseHandle(hEvent);
                } else {
                    CloseHandle(hEvent);
                    CloseHandle(hSharedMem);
                }
            } else {
                CloseHandle(hEvent);
            }
        } else {
        MessageBox(NULL, "Event fail", "DllMain", MB_OK);
        }
        break;
    }
    return TRUE;
}