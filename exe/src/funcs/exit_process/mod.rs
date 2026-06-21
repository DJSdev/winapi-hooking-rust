use windows::Win32::System::Threading::ExitProcess;

use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};

type ExitProcessSig = unsafe extern "system" fn(u32);

pub struct ExitProcessFunc;
impl ExitProcessFunc {
    pub const NAME: &'static str = "ExitProcessFunc";
}
impl HookableFunc for ExitProcessFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("Kernel32.dll", "ExitProcess").unwrap(),
            exit_process_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            ExitProcessFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() -> () {
        unsafe { ExitProcess(0) };
    }
}

#[no_mangle]
pub extern "system" fn exit_process_proxy(exit_code: u32) {
    println!("HOOKED ExitProcess: code {}", exit_code);
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("ExitProcessFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), ExitProcessSig>(p) };
    println!("NOTE: Rust will throw an error due to a non-zero exit code");
    unsafe { orig(42069) }
}
