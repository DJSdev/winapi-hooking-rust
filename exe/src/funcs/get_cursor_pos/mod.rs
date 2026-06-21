use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};
use windows::{
    core::BOOL,
    Win32::{Foundation::POINT, UI::WindowsAndMessaging::GetCursorPos},
};

type GetCursorPosSig = unsafe extern "system" fn(*mut POINT) -> BOOL;

pub struct GetCursorPosFunc;
impl GetCursorPosFunc {
    pub const NAME: &'static str = "GetCursorPosFunc";
}
impl HookableFunc for GetCursorPosFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("user32.dll", "GetCursorPos").unwrap(),
            get_cursor_pos_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            GetCursorPosFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() {
        let mut point = POINT::default();
        unsafe { GetCursorPos(&mut point).unwrap() };
        println!("{point:?}");
    }
}

#[no_mangle]
pub extern "system" fn get_cursor_pos_proxy(lppoint: *mut POINT) -> BOOL {
    println!("HOOKED GetCursorPos");
    println!("  lppoint: {lppoint:?}");

    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("GetCursorPosFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), GetCursorPosSig>(p) };

    let res = unsafe { orig(lppoint) };
    unsafe {
        if !lppoint.is_null() {
            (*lppoint).x = 69;
            (*lppoint).y = 420;
        }
    }
    res
}
