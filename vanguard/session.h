#ifndef SESSION_H
#define SESSION_H
#include <windows.h>

BOOL CreateSessionProcess(unsigned char key[32], unsigned char salt[16]);

BOOL FetchSharedMem(unsigned char key[32], unsigned char salt[16]);

#endif