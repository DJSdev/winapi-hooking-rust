use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::Win32::Foundation::HANDLE;

type NtOpenProcessSig =
    unsafe extern "system" fn(*mut HANDLE, u32, *mut c_void, *mut c_void) -> i32;

pub struct NtOpenProcessFunc;
impl NtOpenProcessFunc {
    pub const NAME: &'static str = "NtOpenProcessFunc";
}
impl HookableFunc for NtOpenProcessFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("ntdll.dll", "NtOpenProcess").unwrap(),
            nt_open_process_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            NtOpenProcessFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() {
        let (func_addr, _) = Self::get_addr_and_proxy();
        let func = unsafe { std::mem::transmute::<*const c_void, NtOpenProcessSig>(func_addr) };
        let mut handle = HANDLE::default();
        let status = unsafe { func(&mut handle, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        println!("NtOpenProcess status: {:x}, handle: {:?}", status, handle);
    }
}

#[no_mangle]
pub extern "system" fn nt_open_process_proxy(
    processhandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut c_void,
    clientid: *mut c_void,
) -> i32 {
    println!("HOOKED NtOpenProcess: access 0x{:x}", desiredaccess);
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("NtOpenProcessFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), NtOpenProcessSig>(p) };
    unsafe { orig(processhandle, desiredaccess, objectattributes, clientid) }
}
