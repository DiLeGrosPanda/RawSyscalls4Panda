## What is it ?
It's a Rust POC to avoid hooks in the ntdll api functions<br/>
My first introduction to this technique was from [RecycledGates](https://github.com/thefLink/RecycledGate/)<br/>
It's implemented by [SysWhispers3](https://github.com/klezVirus/SysWhispers3/) as well

In short, to perform the initial setup, the get_syscalls_list function:
 - Parses NTDLL EAT to find Zw* functions
 - Sorts them by address to get syscalls's id

Then to make a syscall, the make_syscall macro:
 - Ses the registers
 - Sets the stack
 - Calls a "syscall; ret" gadget from ntdll

## Env
Tested on a single Windows 10<br/>
Compiled from Kali using
> cargo build --release --target x86_64-pc-windows-gnu

## Misc infos
Raw syscalls names are hashed.<br/>
Hashes are made using djb2 algorithm (get_syscalls function).<br/>
Values for most functions are available in hash_by_func.txt<br/>
Will panic in debug mode (integer overflow in djb2)

You might find some ntdll.dll unobfuscated string in the binary :)

It should be rather straightforward to use with no_std

## Useful stuff
Great posts on unhooking techniques:
 - https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
 - https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/

Some code taken from:
 - https://github.com/trickster0/OffensiveRust
 - https://github.com/memN0ps/arsenal-rs/

## Disclaimer
Please use it for good and educational purposes.
I'm not responsible for anything you do with this program.
