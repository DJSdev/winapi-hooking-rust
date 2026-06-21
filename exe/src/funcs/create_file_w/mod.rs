use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::Win32::Foundation::HANDLE;

type CreateFileWSig =
    unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, HANDLE) -> HANDLE;

pub struct CreateFileWFunc;
impl CreateFileWFunc {
    pub const NAME: &'static str = "CreateFileWFunc";
}
impl HookableFunc for CreateFileWFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("Kernel32.dll", "CreateFileW").unwrap(),
            create_file_w_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            CreateFileWFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() -> () {
        let (func_addr, _) = Self::get_addr_and_proxy();
        let func = unsafe { std::mem::transmute::<*const c_void, CreateFileWSig>(func_addr) };
        let path: Vec<u16> = "C:\\Windows\\System32\\notepad.exe\0"
            .encode_utf16()
            .collect();
        let handle = unsafe {
            func(
                path.as_ptr(),
                0x80000000,
                1,
                std::ptr::null_mut(),
                3,
                0x80,
                HANDLE::default(),
            )
        };
        println!("CreateFileW handle: {:?}", handle);
    }
}

#[no_mangle]
pub extern "system" fn create_file_w_proxy(
    lpfilename: *const u16,
    dwdesiredaccess: u32,
    dwsharemode: u32,
    lpsecurityattributes: *mut c_void,
    dwcreationdisposition: u32,
    dwflagsandattributes: u32,
    htemplatefile: HANDLE,
) -> HANDLE {
    println!("HOOKED CreateFileW: access {:x}", dwdesiredaccess);
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("CreateFileWFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), CreateFileWSig>(p) };
    unsafe {
        orig(
            lpfilename,
            dwdesiredaccess,
            dwsharemode,
            lpsecurityattributes,
            dwcreationdisposition,
            dwflagsandattributes,
            htemplatefile,
        )
    }
}
