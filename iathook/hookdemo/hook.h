#ifndef HOOK_H
#define HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

void __cdecl hookIAT(LPVOID imageBase, LPCSTR funcName, FARPROC hookedFunction);

#ifdef __cplusplus
}
#endif

#endif // HOOK_H