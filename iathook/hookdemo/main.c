#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define WHITE 0x7
#define GREEN 0x2
#define RED 0x4
#define PE_SIGNATURE 0x4550

int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return MessageBoxW(NULL, L"Hooked MessageBoxA!", L"This call was hooked!", MB_OK);
}

void setColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

BOOL hookIAT(LPVOID moduleBase, LPCSTR funcToHook, FARPROC hookedFunc) {
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
        
        while (originalFirstThunk->u1.AddressOfData != 0) {
            if (originalFirstThunk == NULL || firstThunk == NULL) {
                printf("[!] NULL pointer\n");
            }
            
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);

            if (firstThunk->u1.Function == 0) {
                printf("[i] Skipping null function entry\n");
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
           
            if (strcmp(functionName->Name, funcToHook) == 0) {
                DWORD oldProtect;
                VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                firstThunk->u1.Function = (DWORD_PTR)hookedFunc;
            }
            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return TRUE;
}

int main() {
    MessageBoxA(NULL, "Hello before hooking", "Hello before hooking", MB_OK);
    hookIAT((LPVOID)GetModuleHandleA(NULL), "MessageBoxA", (FARPROC)hookedMessageBox);
    setColor(GREEN);
    printf("[+] Hooked user32.dll!MessageBoxA\n");
    setColor(WHITE);
    MessageBoxA(NULL, "Hello after hooking", "Hello after hooking", MB_OK);
    return 1;
}