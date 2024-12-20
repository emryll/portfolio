#ifndef DETECTOR_H
#define DETECTOR_H

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

#endif