use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::Win32::System::Threading::Sleep;

type SleepSig = unsafe extern "system" fn(u32);

pub struct SleepFunc;
impl SleepFunc {
    pub const NAME: &'static str = "SleepFunc";
}
impl HookableFunc for SleepFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("Kernel32.dll", "Sleep").unwrap(),
            sleep_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE
            .lock()
            .unwrap()
            .insert(SleepFunc::NAME, AtomicPtr::new(trampoline.addr as *mut ()));
    }

    fn invoke() {
        println!("eepy time");
        unsafe { Sleep(5000) };
        println!("waky waky");
    }
}

#[no_mangle]
pub extern "system" fn sleep_proxy(ms: u32) {
    println!("HOOKED Sleep");
    println!("  Milliseconds: {ms:?}");

    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("SleepFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), SleepSig>(p) };

    println!("Actually sleeping for 2 seconds");
    unsafe { orig(2000) };
}
