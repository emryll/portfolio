#include <windows.h>
#include <stdio.h>
#include "session.h"

BOOL CreateSessionProcess(unsigned char key[32], unsigned char salt[16]) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Create the shared memory
    HANDLE hSharedMem = CreateFileMapping(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
        sizeof(unsigned char[32]) + sizeof(unsigned char[16]),
        "vanguard");
    if (hSharedMem == NULL) {
        return FALSE;
    }

    // Map(write) it into this process' memory space
    unsigned char *pBufKey = (unsigned char*)MapViewOfFile(
        hSharedMem,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(unsigned char[32]) + sizeof(unsigned char[16]));
    if (pBufKey == NULL) {
        return FALSE;
    }
    // Mapping has to be page aligned so doing this for salt
    unsigned char *pBufSalt = pBufKey+32;

    // Write key and salt to shared mem
    //! Currently insecure, fixing soon
    memcpy(pBufKey, key, 32);
    memcpy(pBufSalt, salt, 16);
    
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);
    
    BOOL ok = CreateProcess(
        NULL,
        "vanguard.exe -t",
        NULL,
        NULL,
        FALSE,  
        0, 
        NULL,
        NULL,
        &si,
        &pi);
    if (!ok) {
        return FALSE;
    }
    //TODO: Use event
    Sleep(1000);
    CloseHandle(hSharedMem);
    UnmapViewOfFile(pBufKey);
}

// fills key and salt with values from shared mem
BOOL FetchSharedMem(unsigned char key[32], unsigned char salt[16]) {
    //? Why inherit handles??
    HANDLE hSharedMem = OpenFileMapping(FILE_MAP_ALL_ACCESS, TRUE, "vanguard");
    if (hSharedMem == NULL) {
        return FALSE;
    }
    
    unsigned char *pBufKey = (unsigned char*)MapViewOfFile(
        hSharedMem,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(unsigned char[32]) + sizeof(unsigned char[16]));
    if (pBufKey == NULL) {
        return FALSE;
    }
    unsigned char *pBufSalt = pBufKey+32;

    memcpy(key, pBufKey, 32);
    memcpy(salt, pBufSalt, 16);
}