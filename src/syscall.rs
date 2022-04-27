use ntapi::ntldr::{PLDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY};
use ntapi::ntpebteb::PPEB;
use ntapi::ntpsapi::NtCurrentPeb;
use ntapi::ntpsapi::PPEB_LDR_DATA;
use std::ffi::CStr;
use std::mem::transmute;
use std::os::raw::c_char;
use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS};
use std::collections::BTreeMap;

struct SyscallInMemory {
    hash: u32,
    addr: usize
}

// Could/Should be a macro
// Pass args to RCX, RDX, R8, R9
// After 4 args push on the stack in reverse order
//extern "C" fn MyMakeSyscall() {
//    unsafe {
//        asm!(
//            "mov r10, rcx",
//            "syscall"
//        )
//    }
//}
extern "C" {
    pub fn MyMakeSyscall();
}

/// Compares a UNICODE_STRING (*mut 16) with a slice and returns true if equal
fn is_equal(pointer: *mut u16, length: usize, against: &str) -> bool {
    let slice = unsafe { std::slice::from_raw_parts(pointer, length - 1) };
    slice.iter().zip(against.encode_utf16()).all(|(a, b)| *a == b)
}

//unsafe fn get_peb() -> u64 {
//    let peb: u64;
//
//    //asm!(
//    //    "push rbx",
//    //    "xor rbx, rbx",
//    //    "xor rax, rax",
//    //    "mov rbx, qword ptr gs:[0x60]",
//    //    "mov rax,rbx",
//    //    "pop rbx",
//    //    out("rax") peb,
//    //);
//    peb
//}

#[no_mangle]
// Used to setup RAX with the syscall value
// it NEEDS to be be a no_mangle extern "C" function or it might be optimized away
pub unsafe extern "C" fn get_ssn(syscall_list: &BTreeMap<u32, usize>, hash: u32) -> usize {
    //let val = get_syscall_list().and_then(|x| x.iter().position(|i| i.hash == hash)).unwrap() as u32;
    *syscall_list.get(&hash).expect(&format!("Syscall not found for {}", hash))
}

pub unsafe fn get_syscall_list() -> Option<BTreeMap<u32, usize>> {
    let module_name = "ntdll.dll";
    let peb = NtCurrentPeb();

    let ptr_peb_ldr_data = transmute::<*mut _, PPEB_LDR_DATA>((*(peb as PPEB)).Ldr);
    let mut module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*ptr_peb_ldr_data).InLoadOrderModuleList.Flink);

    while !(*module_list).DllBase.is_null() {
        let dll_name = (*module_list).BaseDllName.Buffer;

        if is_equal(dll_name, module_name.len(), module_name) {
            return parse_ntdll_exports(module_list);
        }
        module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*module_list).InLoadOrderLinks.Flink);
    }
    None
}

unsafe fn parse_ntdll_exports(module_list: *mut LDR_DATA_TABLE_ENTRY) -> Option<BTreeMap<u32, usize>> {
    let dll_base = (*module_list).DllBase;
    let dos_header = transmute::<*mut _, PIMAGE_DOS_HEADER>(dll_base);
    let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS>(dll_base as usize + (*dos_header).e_lfanew as usize);
    let export_dir = (dll_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

    assert_eq!(b"ntdll.dll\0", &*((dll_base as usize + (*export_dir).Name as usize) as * const [u8; 10]));

    let names = core::slice::from_raw_parts(
        (dll_base as usize + (*export_dir).AddressOfNames as usize)
        as *const u32,
        (*export_dir).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        (dll_base as usize + (*export_dir).AddressOfFunctions as usize)
        as *const u32,
        (*export_dir).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        (dll_base as usize + (*export_dir).AddressOfNameOrdinals as usize)
        as *const u16,
        (*export_dir).NumberOfNames as _,
    );

    let mut data = Vec::new();
    for i in 0..(*export_dir).NumberOfNames {

        let name = (dll_base as usize + names[i as usize] as usize) as *const c_char;
        if &*(name as *const [u8; 2]) == b"Zw" {
            if let Ok(name) = CStr::from_ptr(name).to_str() {
                let addr = dll_base as usize + functions[ordinals[i as usize] as usize] as usize;
                let hash = name.as_bytes().iter().fold(5381, |acc, x| ((acc << 5) + acc) + *x as u32);
                //println!("{addr} {hash} {name}");
                data.push(SyscallInMemory {addr: addr, hash: hash});
            }
        }
    }
    data.sort_by(|a, b| a.addr.cmp(&b.addr));
    let mut res = BTreeMap::new();

    //data.iter().enumerate().for_each(|(idx,item)| res.insert(idx, item));
    for (idx, item) in data.iter().enumerate() {
        res.insert(item.hash, idx);
    }
    //println!("{:?}", data);
    //println!("{:?}", res);

    return Some(res);
}
