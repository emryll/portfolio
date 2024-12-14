# IAT Hook

# IAT Hook detector
## How it works?
It will fetch all addresses of a process, then it will do that for another process and it will compare 

Needed funcs:
    - Get function addresses
    - Compare function addresses

## How to use?
You can build it from source with gcc (or another compiler)
`gcc hookdetector.c -o hookdetector.exe`
Then to use it:
`./hookdetector.exe [the process PID to scan]`
Or if you only want to get the function addresses of a given process:
`./hookdetector.exe [the process PID to scan] -a`
This will write function addresses to file

By default it will check all KnownDLLs, but you can also specify a dll (only works for KnownDLLs)