use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::core::BOOL;

type IsDebuggerPresentSig = unsafe extern "system" fn() -> BOOL;

pub struct IsDebuggerPresentFunc;
impl IsDebuggerPresentFunc {
    pub const NAME: &'static str = "IsDebuggerPresentFunc";
}
impl HookableFunc for IsDebuggerPresentFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("Kernel32.dll", "IsDebuggerPresent").unwrap(),
            is_debugger_present_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            IsDebuggerPresentFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() -> () {
        let (func_addr, _) = Self::get_addr_and_proxy();
        let func = unsafe { std::mem::transmute::<*const c_void, IsDebuggerPresentSig>(func_addr) };
        println!("IsDebuggerPresent: {:?}", unsafe { func() });
    }
}

#[no_mangle]
pub extern "system" fn is_debugger_present_proxy() -> BOOL {
    println!("HOOKED IsDebuggerPresent");
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("IsDebuggerPresentFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), IsDebuggerPresentSig>(p) };
    unsafe { orig() }
}
