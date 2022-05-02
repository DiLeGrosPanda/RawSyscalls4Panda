use crate::ffi_ctypes::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY, LDR_DATA_TABLE_ENTRY,
    PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, PLDR_DATA_TABLE_ENTRY, PPEB, PPEB_LDR_DATA, PVOID,
};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::transmute;

#[derive(Debug)]
pub struct SyscallInMemory {
    pub id: usize,
    pub addr: usize,
}

pub const DISTANCE_TO_SYSCALL: usize = 0x12;
pub const SYSCALL_AND_RET: [u8; 3] = [0x0f, 0x05, 0xc3];

/// Compares a UNICODE_STRING (*mut 16) with a slice and returns true if equal
fn is_equal(pointer: *mut u16, length: usize, against: &str) -> bool {
    let slice = unsafe { core::slice::from_raw_parts(pointer, length - 1) };
    slice
        .iter()
        .zip(against.encode_utf16())
        .all(|(a, b)| *a == b)
}

unsafe fn get_peb() -> u64 {
    let peb: u64;

    // ntapi::ntpsapi::NtCurrentPeb()
    core::arch::asm!(
        "push rbx",
        "xor rbx, rbx",
        "xor rax, rax",
        "mov rbx, qword ptr gs:[0x60]",
        "mov rax,rbx",
        "pop rbx",
        out("rax") peb,
    );
    peb
}

pub unsafe fn get_syscall_list() -> Option<BTreeMap<u32, SyscallInMemory>> {
    let module_name = "ntdll.dll";
    let peb = get_peb();

    let ptr_peb_ldr_data = transmute::<*mut _, PPEB_LDR_DATA>((*(peb as PPEB)).Ldr);
    let mut module_list =
        transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*ptr_peb_ldr_data).InLoadOrderModuleList.Flink);

    while !(*module_list).DllBase.is_null() {
        let dll_name = (*module_list).BaseDllName.Buffer;

        if is_equal(dll_name, module_name.len(), module_name) {
            return parse_ntdll_exports(module_list);
        }
        module_list =
            transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*module_list).InLoadOrderLinks.Flink);
    }
    None
}

unsafe fn parse_ntdll_exports(
    module_list: *mut LDR_DATA_TABLE_ENTRY,
) -> Option<BTreeMap<u32, SyscallInMemory>> {
    let dll_base = (*module_list).DllBase;
    let dos_header = transmute::<*mut _, PIMAGE_DOS_HEADER>(dll_base);
    let nt_headers =
        transmute::<usize, PIMAGE_NT_HEADERS>(dll_base as usize + (*dos_header).e_lfanew as usize);
    let export_dir = (dll_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    assert_eq!(
        b"ntdll.dll\0",
        &*((dll_base as usize + (*export_dir).Name as usize) as *const [u8; 10])
    );

    let names = core::slice::from_raw_parts(
        (dll_base as usize + (*export_dir).AddressOfNames as usize) as *const u32,
        (*export_dir).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        (dll_base as usize + (*export_dir).AddressOfFunctions as usize) as *const u32,
        (*export_dir).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        (dll_base as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16,
        (*export_dir).NumberOfNames as _,
    );

    get_syscalls(dll_base, export_dir, names, functions, ordinals)
}

unsafe fn get_syscalls(
    dll_base: PVOID,
    export_dir: *mut IMAGE_EXPORT_DIRECTORY,
    names: &[u32],
    functions: &[u32],
    ordinals: &[u16],
) -> Option<BTreeMap<u32, SyscallInMemory>> {
    let mut syscalls = Vec::new();
    for i in 0..(*export_dir).NumberOfNames {
        let mut name = (dll_base as usize + names[i as usize] as usize) as *const u8;
        if &*(name as *const [u8; 2]) == b"Zw" {
            // std::ffi::CStr::from_ptr(name).to_str()
            //.as_bytes().iter().fold(5381, |acc, x| ((acc << 5) + acc) + *x as u32);
            let mut hash = 5381;
            while *name != b'\0' {
                hash = ((hash << 5) + hash) + (*name as u32);
                name = (name as u64 + 1) as *const u8;
            }
            let addr = dll_base as usize + functions[ordinals[i as usize] as usize] as usize;
            syscalls.push((hash, addr));
        }
    }
    syscalls.sort_by(|a, b| a.1.cmp(&b.1));
    let mut res = BTreeMap::new();

    for (idx, item) in syscalls.iter().enumerate() {
        res.insert(
            item.0,
            SyscallInMemory {
                id: idx,
                addr: item.1,
            },
        );
    }

    return Some(res);
}

// TODO Could be safe without from_raw_parts
/// Look for "syscall; ret" inside ntdll at func_base_addr + DISTANCE_TO_SYSCALL
/// Priorize the syscall function matching the hash parameter
pub unsafe fn find_syscall_and_ret(
    syscall_list: &BTreeMap<u32, SyscallInMemory>,
    hash: u32,
) -> SyscallInMemory {
    let syscall = syscall_list
        .get(&hash)
        .expect(&format!("Syscall not found for {}", hash));
    let is_valid = |sc: &&SyscallInMemory| {
        core::slice::from_raw_parts(
            (sc.addr as usize + crate::syscall::DISTANCE_TO_SYSCALL) as *const u8,
            3,
        ) == crate::syscall::SYSCALL_AND_RET
    };

    if is_valid(&syscall) {
        println!("Found valid SYSCALL_AND_RET for {hash}");
        return SyscallInMemory {
            id: syscall.id,
            addr: syscall.addr + crate::syscall::DISTANCE_TO_SYSCALL,
        };
    }

    println!("Looking for an alternative SYSCALL_AND_RET for {hash}");
    match syscall_list
        .values()
        .filter(is_valid)
        .collect::<Vec<_>>()
        .first()
    {
        Some(sc) => SyscallInMemory {
            id: syscall.id,
            addr: sc.addr + crate::syscall::DISTANCE_TO_SYSCALL,
        },
        None => panic!("Couldn't find any valid SYSCALL_AND_RET for {hash}"),
    }
}

#[macro_export]
macro_rules! make_syscall {
    // 0 arguments
    ($syscall_list: expr, $hash: expr) => {{
        let syscall = crate::syscall::find_syscall_and_ret($syscall_list, $hash);
        let mut rax = syscall.id;

        core::arch::asm!(
            "/* */",
            "mov r10, rcx",
            "call {0}",
            in(reg) syscall.addr,
            inout("rax") rax
        );
        rax
    }};

    // 5 arguments
    ($syscall_list: expr, $hash: expr, $arg_1: expr, $arg_2: expr, $arg_3: expr, $arg_4: expr, $arg_5: expr) => {{
        let syscall = crate::syscall::find_syscall_and_ret($syscall_list, $hash);
        let mut rax = syscall.id;
        core::arch::asm!(
            "/* */",
            "mov [rsp], {0}",
            "sub rsp, 0x20",
            "mov r10, rcx",
            "call {1}",
            "add rsp, 0x20",
            in(reg) $arg_5,
            in(reg) syscall.addr,
            in("rcx") $arg_1,
            in("rdx") $arg_2,
            in("r8") $arg_3,
            in("r9") $arg_4,
            inout("rax") rax
        );
        rax
    }};

    // 6 arguments
    ($syscall_list: expr, $hash: expr, $arg_1: expr, $arg_2: expr, $arg_3: expr, $arg_4: expr, $arg_5: expr, $arg_6: expr) => {{
        let syscall = crate::syscall::find_syscall_and_ret($syscall_list, $hash);
        let mut rax = syscall.id;
        core::arch::asm!(
            "/* */",
            "mov [rsp - 0x08], {0}",
            "mov [rsp], {1}",
            "sub rsp, 0x28",
            "mov r10, rcx",
            "call {2}",
            "add rsp, 0x28",
            in(reg) $arg_5,
            in(reg) $arg_6,
            in(reg) syscall.addr,
            in("rcx") $arg_1,
            in("rdx") $arg_2,
            in("r8") $arg_3,
            in("r9") $arg_4,
            inout("rax") rax
        );
        rax
    }};
}
