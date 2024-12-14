# Coding portfolio
Contact me at: **segfault@mailfence.com**

This is an overview of the projects, each project folder contains a more detailed write-up in the README file.

### About me
I'm 19 years old and I'm passionately curious. I love learning and I'm especially interested in cybersecurity, OS internals and everything low-level! My programming journey started at around 11 years old when my dad introduced me to Python, as well as Linux. I did have a break in the middle but I've been coding a lot for the past 4 years.

The past few years I've been using Golang and C as well as learning a bit of assembly recently. I've been studying computer science and OS internals.
I've also been studying a lot about cybersecurity, low-level technical stuff, malware detection, -prevention, how attacks typically happen and how to prevent it.
I've actually been planning on making my own EDR from scratch! Check out the write-up and charts.

I'm a very curious person and have always been. I'm always wondering: "How does this work? How does this actually work under the hood?".
I keep diving deeper into the rabbit hole of information..

My other hobbies; art and skateboarding also give me an edge when it comes to programming and cybersecurity, let me elaborate:
    - Art teaches creative thinking, not only for creating visual stuff, but also for thinking outside of the box, approaching problems differently.
    - In skateboarding you have to try a trick 1000 times before you get it. Skateboarding teaches you to keep trying, getting hit, falling down, but still getting up and trying again.
This all contributes to a 'hacker mentality'; curiosity, resilience and creativity.

I do not yet have a degree, as I haven't started university yet, but that is incoming in a few years. I'm getting a masters in computer science.

## Static malware analysis engine and React front-end
I learned React just for this.
#### What is it?
A website to which you can upload a file, this file will then get sent to the server and fed to a static malware analysis engine, which will score it on different tests performed, and then a final score is calculated based on these results, this final score is a number 0-100, describing how certain the engine is of it being malicious, 100 being definitely malicious.

The tests include:
    - A large list of YARA rules, including rules for detecting different process injection techniques.
    - Examining imports via PEB walk and PE parsing
    - Traditional hash-based signatures

Front-end written with React.

#### Why?
I am deeply passionate about computer science and cybersecurity. The past year or two I've been reading about this kind of stuff a lot, this was a very fun project for me!
While this won't detect some more advanced malware, this should still detect known malware and a majority of less sophisticated malware.

## At-rest encryption CLI-tool
#### What is it?
A tool for protecting important files with a CLI serving as the UI. First of all you create a password, then you can set files and folders under protection (to be encrypted with password). The normal state of a protected file is to be encrypted (encryption at-rest), then by logging on in the CLI, you can release selected files/folders (decrypt them),
which will start a 'session', which is essentially just a timer in a seperate process. Session length can be controlled by the user, but by default it is 30min.
After this session timer runs out, processes with file open will be shut down and the file will be locked again, asking for password to re-release.

#### Why?
I decided to make this because while setting up a new computer I realized I need a tool to secure important files at-rest.
Then I thought it would be a great portfolio project and relatively simple to make.

## Custom implementation of GetProcAddress and GetModule
#### What is it?
Custom implementation of Windows GetProcAddress and GetModule API functions, which get function addresses and the base address of a given module in memory.
This is done by parsing the Process Environment Block(PEB) to find and retrieve the given module and its base address (GetModule),
then parsing the PE file headers in memory, located at module base address. This is done by getting Export Address Table(EAT) through the optional header, and then going through the 3 arrays in the EAT (AddressOfNames, AddressOfNameOrdinals and AddressOfFunctions)

#### Why?
This project demonstrates my deep Windows internals knowledge, showcasing parsing of the PEB structure, PE file headers, as well as understanding of how processes work, memory and PE file structure.

In the real world this is something that malware may implement as an attempt to avoid detection.
AV/EDR products often hook Windows API functions to be able to intercept these calls and examine if it seems like a malicious call.
A custom implementation of GetProcAddress and GetModule allows the bypassing of these hooks in resolving of function addresses, which can then be used in other techniques like (In)Direct syscalls and IAT hooking.

For cyber security professionals, the defending party, it is critical to understand how the attackers may attack, in order to protect against this.
For example what I would do to detect this technique, is create a YARA rule for this parsing of PE headers and PEB, as these offsets are constant and this is not something benign programs typically do.

## IAT hook and IAT hook detector
#### What is it?
Import Address Table(IAT) hooking demonstration as well as a detection mechanism I came up with. Modern programs use shared libraries for modularity. When a program calls an imported shared library function, it will basically say: jump to the address, which is located in the IAT at position n, then it will execute the function located at that address in memory.
With IAT hooking, the address is changed to point to a different function, so when function A is called, it will actually point to function B, executing that code.

#### My approach to IAT hook detection
I almost immediately got the idea that since KnownDLLs (like kernel32.dll and ntdll.dll) are located at the same address across processes for memory efficiency, you can get the function addresses from two processes and compare them, to see if one of them is hooked. Assuming you can't know for sure any single process is not hooked, you would have to check a third one to see which 2 are correct. It would still be possible that all those are hooked resulting on a false negative, but that would be unlikely.

After a little bit I realized I could instead just compare against the EAT addresses. It is possible to hook the EAT although less common and a little bit more tricky,
however when this is integrated to an EDR or similar, you can compare every processes addresses, there is no way(realistically) that all of the IATs and EATs in all the processes would be hooked.

This IAT hook detector will check if a given process' modules' IATs are hooked. Due to the modular design, this can be easily integrated into an EDR, by looping through processes and calling this binary for them. In this real-world use-case, it will actually be more accurate, since we have now checked every address, so if one is different, that means a hook.

#### Why?
IAT hooking is a commonly used technique by malware and security products, this IAT hook detector binary is also modular, so I can seemlessly incorporate it into my upcoming EDR project!

## Syswhispers2 proof-of-concept
#### What is it?
Syswhispers2 is a smart technique of resolving System Service Numbers(SSN) as well as function addresses. The way this works is, first you walk the PEB to find the target module.
Then you go to the image base address of that module where the PE headers are located. Then you parse the PE headers to get to the Export Address Table(EAT), there you go through the AddressOfNames array and save every Zw function (Nt and Zw functions point to same code and are the same in usermode). You get addresses through the other 2 arrays, AddressOfNameOrdinals and AddressOfFunctions.
Once you have all Zw functions and their addresses, you can simply sort them by address, because SSNs are in order. 0th Zw function will have SSN 0, and so on.

#### My approach for detection
Since this is based on walking the PEB and parsing the PE headers, which is abnormal for benign applications, this is what I would use to detect this (and a lot of similar stuff).
The offsets are fixed so you can create a YARA rule to detect it. Just getting the PEB should raise red flags (x64:*GS+0x60* / x86:*FS+0x30*)

#### Why?
This is a technique used by both attackers and defenders and can be used to create position independent code. In particular attackers usually use this technique for (In)Direct syscalls, or a similar technique of bypassing userland API hooks.

## Projects in the pipeline
Check out the Projects in the pipeline folder for projects which I have planned out but not yet gotten to coding them, as I'm coding something else.
    - Custom EDR from scratch!
    - 