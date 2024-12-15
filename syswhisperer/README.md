# Syswhispers2 Proof-of-concept
## What is it?
Syswhispers2 is a smart technique of resolving System Service Numbers(SSN) as well as function addresses.

The way this works is, first you walk the PEB to find the target module and save the base address.

Then you go to the image base address of that module, which is where the PE headers are located. Then you parse the PE headers to get to the Export Address Table(EAT), a data directory found in the optional headers.

From there you go through the AddressOfNames array and save every Zw function. You get addresses through the other 2 arrays, AddressOfNameOrdinals and AddressOfFunctions.

For a more detailed explanation see the [custom GetProcAddress implementation](parser/README.md)

Once you have all Zw functions and their addresses, you can simply sort them by address, because SSNs are in order. 0th Zw function will have SSN 0, and so on.

The reason for using Zw functions is because Syswhispers2 is an evolution of FreshyCalls, which do the same but with Nt functions.
With Nt you cannot just search for Nt prefix, you need to also check that it doesn't start with Ntdll.
Zw functions point to the same code and effectively are the same in user mode, so this is a clever optimization to FreshyCalls.

## Why?
This is a technique used by both attackers and defenders and can be used to create position independent code. In particular attackers usually use this technique for (In)Direct syscalls, or a similar technique of bypassing userland API hooks.

## My approach for detection
Since this is based on walking the PEB and parsing the PE headers, which is abnormal for benign applications, this is what I would use to detect this (and a lot of similar stuff).
The offsets are fixed so you can create a YARA rule to detect it. Just getting the PEB should raise red flags (x64:*GS+0x60* / x86:*FS+0x30*)
