#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define WHITE 0x7
#define GREEN 0x2
#define RED 0x4
#define PE_SIGNATURE 0x4550

//? I use offsets instead of names, because I had some issues, since these aren't properly documented by Microsoft.
//? You can find the offsets at geoffchappell.com

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

int main() {
    //? This is just so ntdll would show up, if it doesn't implicitly
    //LoadLibrary("ntdll.dll");
    //SYSTEM_BASIC_INFORMATION sbi;
    //NTSTATUS status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), NULL);

    PVOID nt = getModuleBase(L"ntdll.dll");
    if (nt == NULL) {
        setColor(RED);
        printf("\n[!] Custom GetModuleHandleA failed on ntdll. This may be because it's not explicitly loaded/used in the code\n");
        setColor(WHITE);
        return -1;
    }
    
    PVOID exe = getModuleBase(NULL);
    if (exe == NULL) {
        setColor(RED);
        printf("\n[!] Custom GetModuleHandleA failed on main module...\n");
        setColor(WHITE);
        return -1;
    }
    
    PVOID k32 = getModuleBase(L"kernel32.dll");
    if (k32 == NULL) {
        setColor(RED);
        printf("\n[!] Custom GetModuleHandleA failed on kernel32\n");
        setColor(WHITE);
        return -1;
    }

    PVOID realK32 = GetModuleHandleA("kernel32.dll");
    PVOID realNt = GetModuleHandleA("ntdll.dll");
    PVOID realExe = GetModuleHandleA(NULL);
    printf("\n================================================\n");
    printf("\ngetModuleBase(L\"ntdll.dll\"):      %#X\nGetModuleHandleA(\"ntdll.dll\"):    %#X\n\ngetModuleBase(NULL):              %#X\nGetModuleHandleA(NULL):           %#X\n\ngetModuleBase(L\"kernel32.dll\"):   %#X\nGetModuleHandleA(\"kernel32.dll\"): %#X\n", nt, realNt, exe, realExe, k32, realK32);
    if (nt == realNt && k32 == realK32 && exe == realExe) {
        setColor(GREEN);
        printf("\n[+] Custom GetModuleHandleA works as it should!\n");
        setColor(WHITE);
    } else {
        setColor(RED);
        printf("\n[!] Custom GetModuleHandleA did not work :(\n");
        setColor(WHITE);
        return -1;
    }
    printf("\n================================================\n\n");

    PVOID addr = getFuncAddress(nt, "NtQuerySystemInformation");
    PVOID a = GetProcAddress(realNt, "NtQuerySystemInformation");

    printf("\n================================================\n");
    printf("\ngetFuncAddress for NtQuerySystemInformation: %#X\nGetProcAddress for NtQuerySystemInformation: %#X\n", addr, a);
    if (addr == a) {
        setColor(GREEN);
        printf("\n[+] Custom GetProcAddress works as it should!\n");
        setColor(WHITE);
    } else {
        setColor(RED);
        printf("\n[!] Custom GetProcAddress did not work :(\n");
        setColor(WHITE);
    }
    printf("\n================================================\n");
    return 1;
}