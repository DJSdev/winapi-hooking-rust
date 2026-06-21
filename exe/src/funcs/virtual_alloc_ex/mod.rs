use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::Win32::Foundation::HANDLE;

type VirtualAllocExSig =
    unsafe extern "system" fn(HANDLE, *const c_void, usize, u32, u32) -> *mut c_void;

pub struct VirtualAllocExFunc;
impl VirtualAllocExFunc {
    pub const NAME: &'static str = "VirtualAllocExFunc";
}
impl HookableFunc for VirtualAllocExFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("Kernel32.dll", "VirtualAllocEx").unwrap(),
            virtual_alloc_ex_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            VirtualAllocExFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() -> () {
        let (func_addr, _) = Self::get_addr_and_proxy();
        let func = unsafe { std::mem::transmute::<*const c_void, VirtualAllocExSig>(func_addr) };
        let current_process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
        let ptr = unsafe {
            func(
                current_process,
                std::ptr::null(),
                0x1000,
                0x1000 | 0x2000,
                0x40,
            )
        };
        println!("VirtualAllocEx allocated: {:?}", ptr);
    }
}

#[no_mangle]
pub extern "system" fn virtual_alloc_ex_proxy(
    hprocess: HANDLE,
    lpaddress: *const c_void,
    dwsize: usize,
    flallocationtype: u32,
    flprotect: u32,
) -> *mut c_void {
    println!("HOOKED VirtualAllocEx: size 0x{:x}", dwsize);
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("VirtualAllocExFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), VirtualAllocExSig>(p) };
    unsafe { orig(hprocess, lpaddress, dwsize, flallocationtype, flprotect) }
}
