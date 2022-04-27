## Misc infos
Raw syscalls names are hashed.<br/>
Hashes are made using djb2 algorithm (get_ssn function).<br/>
Values for most functions are available in hash_by_func.txt<br/>
That being said, you might find some ntdll.dll unobfuscated string in the binary :)

I chose to build/link an asm file to be able to make the syscalls.<br/>
You can write a simple macro to use Rust inline asm feature, and hide Windows's calling convention.<br/>
A better aproach might be to patch ntdll to avoid raw syscalls and hooks ([RecycledGates](https://github.com/thefLink/RecycledGate/))

Will panic in debug mode (integer overflow in djb2)<br/>

## Env
Tested on a single Windows 10<br/>
Compiled from Kali using
> cargo build --release --target x86_64-pc-windows-gnu

## Useful stuff
Useful link for AES encryption:
* https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')AES_Encrypt(%7B'option':'UTF8','string':'MySecuredKey123%2B'%7D,%7B'option':'Hex','string':'000102030405060708090A0B0C0D0E0F'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D)To_Hex('%5C%5Cx',0)

Great posts on unhooking:
 - https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
 - https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/

Some code taken from:
 - https://github.com/trickster0/OffensiveRust
 - https://github.com/memN0ps/arsenal-rs/


## Disclaimer
I'm not responsible for whatever you do with it.<br/>
The code comes with no guarantee, unsafe everywhere, way too many assumptions, and pretty much no error handling.
