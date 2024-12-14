### How to use?
You can find a binary in the bin/ folder, or compile it yourself from source.
I compiled with gcc:
```gcc parser.c -o parser.exe```
```.\parser.exe```

## Custom GetModule
### What is it?
It is a manual implementation of the windows API function **GetModuleHandleA**.
Given the name of the module (or *NULL* for the main module, the executable), it will get the base address of a module.

### How?
This works through a Process Environment Block(PEB) walk: First you get the PEB address, then you navigate to modules list and find the right one, then you get the DllBase.

[ graph here ]

## Custom GetProcAddress
### What is it?
It is a manual implementation of the windows API function **GetProcAddress**.
Given the base address of the module and name of function, it will return the address of that function.

### How?
GetProcAddress goes to the base of the given module (HANDLE is the same as the base address) where the PE headers are located. All exes, and dlls are PE files and have these headers.
It will then parse the headers to find the Export Address Table (IMAGE_DIRECTORY_ENTRY_EXPORT).
Inside that, there are 3 important arrays: AddressOfNames, AddressOfNameOrdinals and AddressOfFunctions.
First it will go through the AddressOfNames until it finds the target function. Then this index(1) inside AddressOfNameOrdinals, is the index(2) for AddressofFunctions,
and that is the address of the function in this processes memory.

[ graph here ]

I'm using offsets instead of the names, because these structures are deeply internal and Microsoft seems to believe in security through obscurity, so a lot of this is undocumented,
and windows.h and winternl.h have a lot of 'Reserved' fields in structures, so I'm using offsets. Offsets are not an issue, as they don't change through versions(or more specifically, these fields don't).
