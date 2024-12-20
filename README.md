# Coding portfolio
Contact me at: **segfault@mailfence.com**

**THIS IS NOT YET READY**

If you're unfamiliar with Windows internals, you should first read [BACKGROUND.md](BACKGROUND.md), for explanations of relevant concepts.

This is an overview of the projects, each project folder contains a more detailed write-up in the README file.

### About me
I'm 19 years old and I'm passionately curious. I love learning and I'm especially interested in cybersecurity, OS internals and everything low-level! My programming journey started at around 11 years old when my dad introduced me to Python, as well as Linux. I did have a break in the middle but I've been coding a lot for the past 4 years.

The past few years I've been using Golang and C as well as learning a bit of assembly recently. I've been studying computer science and OS internals.
I've also been studying a lot about cybersecurity, low-level technical stuff, malware detection, -prevention, how attacks typically happen and how to prevent them.
I've actually been planning on making my own EDR from scratch!

I'm a very curious person and have always been. I'm always wondering: "How does this work? How does this actually work under the hood?".
I keep diving deeper into the rabbit hole of information..

My other hobbies; art and skateboarding also give me an edge when it comes to programming and cybersecurity, let me elaborate:
    * **Art** teaches creative thinking, not only for creating visual stuff, but also for thinking outside of the box, approaching problems differently.
    * In **skateboarding** you have to try a trick 1000 times before you get it. Skateboarding teaches you to keep trying, getting hit, falling down, but still getting up and trying again.

This all contributes to a 'hacker mentality'; curiosity, resilience and creativity.

I do not yet have a degree, as I haven't started university yet, but that is incoming in a few years. I'm getting a masters in computer science.

## [At-rest encryption CLI-tool](vanguard/README.md)
#### What is it?
A tool for protecting important files with an interactive shell and CLI commands serving as the UI.

You can `protect` files or folders, meaning they will be encrypted with a password and added into a local database. If the database doesn't exist it will be created automatically. You can also set a group for the files, this serves as sort of a category so you can select certain files more easily.

The normal state of a protected file is to be encrypted (encryption at-rest), then you can `open` a file, folder, group or all the protected files.
I'm working on a **session** feature, which would start here, essentially just a timer in a seperate process. Session length can be controlled by the user, but by default it is 30min.
After this session timer runs out, processes with file open will be shut down and the file will be locked again, asking for password to re-release.

You can also `get` files, folders, groups or all entries from the database.

#### Why?
I decided to make this, because while setting up a new computer, I realized I need a tool to secure important files at-rest and during transfer between devices.
Then I thought it would be a great portfolio project and relatively simple to make.

## [Custom implementation of GetProcAddress and GetModule](parser/README.md)
#### What is it?
Custom implementation of Windows GetProcAddress and GetModule API functions, which get function addresses and the base address of a given module in memory.

This is done by parsing the Process Environment Block(PEB) to find and retrieve the given module and its base address (*GetModuleHandleA*),
then parsing the PE file headers, located at module base address, in order to get address of the EAT.

The function addresses are then retrieved from the Export Address Table(EAT), by going through the 3 arrays in the EAT (AddressOfNames, AddressOfNameOrdinals and AddressOfFunctions)

#### Why?
This project demonstrates my **deep Windows internals knowledge**, showcasing my understanding of how processes work, memory and PE file structure as well as **parsing the PEB structure and PE headers**.

In the real world this is something that malware may implement as an attempt to avoid detection, because AV/EDR products often hook Windows API functions to be able to intercept these calls and examine if it seems like a malicious call.

A custom implementation of **GetProcAddress** and **GetModuleHandleA** allows the bypassing of these hooks in resolving of function addresses, which can then be used in other techniques like (In)Direct syscalls and IAT hooking.

For cyber security professionals, the defending party, it is **critical** to understand how the attackers may attack, in order to protect against this.

For example what I would do to detect this technique, is create a **YARA rule** for this parsing of PE headers and PEB, as these offsets are constant and this is not something benign programs typically do, since normally the system handles this for you.

## [IAT hook POC and IAT hook detector](iathook/README.md)
#### What is it?
Import Address Table(IAT) hooking demonstration as well as a detection mechanism I came up with.

For each imported function a module imports, the [Import Address Table](BACKGROUND.md) contains an entry connecting the function name to an address in memory.
When a program calls an imported function, what happens is the system will get the corresponding entry in the IAT and jump to that address.

With IAT hooking, the address is changed to point to a different function, so when function A is called, it will actually point to function B, executing that code.

#### My approach to IAT hook detection
I'm detecting IAT hooking by injecting a DLL into the target process, which will then compare a functions addresses in the Import Address Table and Export Address Table to see if they match.
It is technically possible to hook both IAT and EAT, however this is unlikely.

#### Why?
IAT hooking is a commonly used technique by malware and security products, this IAT hook detector binary is also modular, so I can seemlessly incorporate it into my upcoming EDR project!

## [Syswhispers2 Proof-Of-Concept](syswhisperer/README.md)
#### What is it?
Syswhispers2 is a smart technique of resolving System Service Numbers(SSN) as well as function addresses. This is done through a *PEB walk* to obtain ntdll's base address.
Then parsing the PE headers to get the Export Address Table. There you can get every Zw function (Nt and Zw functions point to same code and are the same in usermode). With a list of all Zw functions and their addresses, you can simply sort them by address, because SSNs are in order. 0th Zw function will have SSN 0, and so on.

#### Why?
This is a technique used by both attackers and defenders and can be used to create position independent code. In particular attackers usually use this technique for (In)Direct syscalls, or a similar technique of bypassing userland API hooks.

## Projects in the pipeline
Check out the Projects in the pipeline folder for projects which I have planned out but not yet gotten to coding them, as I'm coding something else.
    * Static malware analysis engine and React frontend
    * Custom EDR from scratch: An advanced cybersecurity tool to detect and mitigate threats in real-timek detector](iathook/README.md)
