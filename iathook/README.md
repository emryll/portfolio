# IAT Hook

# IAT Hook detector
![screenshot](rsrc/detection.PNG)
## How it works?
It will go through all modules of a process, looping through every function, comparing the address to that of the EAT.
I realized I would need to remotely walk the PEB and have IAT and EAT parsing functions for a remote process, which seemed
like a major headache, so I decided to instead make a program that scans it's own memory, and then inject this into the target with simple DLL injection.

This project consists of: shared memory IPC with events, [PEB walk and PE parsing](../parser/README.md), going through the IAT, [going through the EAT](../parser/README.md) and DLL injection.

## Bypassing detection
This kind of detection could be bypassed by hooking both the IAT and the EAT of the target function.

## How to use?
You can build it from source with gcc (or another compiler)
(it has to be named **detector.dll** because this is hardcoded in the logic..)
`gcc hookdetector.c -shared -o detector.dll`
`gcc main.c -o detector.exe`
Then to use it:
`./detector.exe [the process PID to scan]`
Or if you only want to get the function addresses of a given process:
`./detector.exe [the process PID to scan] -a`
This will write function addresses to file

