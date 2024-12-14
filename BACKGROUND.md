# Relevant background about Windows internals

## Windows API
On windows syscalls are handled through a set of DLLs. Syscalls are how a normal application interacts with the kernel

The DLL developers are supposed to use is *kernel32.dll*, these functions are well documented by Microsoft. When you call a kernel32 function, it will call a *kernelbase.dll* function, which will finally call a *ntdll.dll* function.

Ntdll is older and works as the foundation for kernel32 and kernelbase functions, which are more user friendly.
Ntdll is mostly undocumented by Microsoft, however skilled reverse-engineers have figured out a lot of things.
These functions provide far more specific control, but you may need to do a lot of stuff manually that the kernel32/kernelbase functions do for you and the functions are more complicated to use.
Ntdll is used for core system functionality, so every process loads ntdll.

Ntdll is what will actually make the syscall, making the connection between user-land and kernel-land. The kernel will then run the corresponding code for the function.

## Processes
A process is just a container. A process has an access token, a private memory space, and can have threads, executable images and handles, which can be thinked of as tools 

An application can have multiple processes, which can talk to each other with interprocess communication methods like pipes or shared memory. A thread is what executes code.
### Shared libraries
Modern applications will use shared libraries for modularity. This means that multiple programs can use the same code(library). It will be loaded into the processes memory space if it uses that library

### Process Environment Block (PEB)
The PEB is the user mode representation of a process.
It has a lot of information about the process, for example: a value indicating if the process is being debugged, a list of loaded modules (including the main executable), and information about all these modules, including the address it resides at in this process' memory

When a process is created, the PEB will be created and filled.

You can get the address of the PEB by adding *0x60* to GS register for x64, or adding *0x30* to FS register on x86

## PE Files
Portable Executable(PE) files are a file format for executables on Windows.
.exe files arent the only PE files, this also includes DLLs(windows shared library), SRVs(kernel modules) among others.

### PE Headers
Every PE file has headers at the beginning of the file. For these projects what interests us is the Optional header inside NT headers. This contains a data directory array of interest, let's go over 2 of the data directories
#### Import Address Table(IAT)
The Import Address Table is basically what translates imported functions to code.
When you call an imported function, it will go to IAT and jump to the address connected to that function name. Each module has their own IAT

IAT hooking project README goes over this structure in more detail

#### Export Address Table(EAT)
The export address is similar to IAT in purpose, but instead of imports it's exports, the functions other modules import.

Custom GetProcAddress project README goes over this structure in more detail

## Process Injection
To avoid detection, malware will often make a benign application run the malicious code. The code is generally either shellcode(position independent), which can run directly when placed in executable memory, or a DLL which the target application will load.

## AV/EDR API monitoring
Because many attack techniques require API calls(syscalls actually), AV/EDR does something called hooking, to intercept API calls during runtime.

So basically, inside of the API function, a jump will be inserted, so that when you run the API function it will first redirect execution(jump) to the AVs or EDRs code that will look at the call and determine if it's malicious or not. If it's not malicious, it will let the API function execute, otherwise it will stop it.

It's also possible to hook syscalls directly in kernel mode, but I'm only covering user mode inline hooking here.

## Common API hook bypasses
### Replacing hooks
A simple approach to bypassing API hooking, would be to overwrite with a clean copy of the dll, and (theoretically) AV/EDR can't see your API calls. However AV/EDR can scan it to check if the hooks have been removed. If they have, this is a clear indication of compromise(IOC)

### Direct syscalls
Another approach is to make the syscalls yourself. In order to make the syscall, you will need the System Service Number(SSN), which basically tells the kernel which syscall you want.

The problem here is that syscalls should only ever be executed in ntdll memory, so this is a clear IOC.

### Indirect syscalls
A natural evolution of direct syscalls, indirect syscalls will instead jump to ntdll for the syscall, this way it looks like the syscall is coming from ntdll. The callstack will look suspicious.