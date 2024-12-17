#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, "DLL Loaded (DLL_PROCESS_ATTACH)", "DllMain", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        MessageBox(NULL, "DLL Unloaded (DLL_PROCESS_DETACH)", "DllMain", MB_OK);
        break;
    }
    return TRUE;
}