use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::DataExchange::GetClipboardData,
};

type GetClipboardDataSig = unsafe extern "system" fn(u32) -> HANDLE;

pub struct GetClipboardDataFunc;
impl GetClipboardDataFunc {
    pub const NAME: &'static str = "GetClipboardDataFunc";
}
impl HookableFunc for GetClipboardDataFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("user32.dll", "GetClipboardData").unwrap(),
            get_clipboard_data_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            GetClipboardDataFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() {
        let c_data = unsafe { GetClipboardData(0) };
        match c_data {
            Ok(data) => println!("{:?}", data),
            Err(err) => {
                let last_err = unsafe { GetLastError() };
                println!("{last_err:?} {err}");
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn get_clipboard_data_proxy(u_format: u32) -> HANDLE {
    println!("HOOKED GetClipboardData");
    println!("  u_format: {u_format:?}");

    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("GetClipboardDataFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), GetClipboardDataSig>(p) };
    unsafe { orig(u_format) }
}
