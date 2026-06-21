use std::{ffi::c_void, sync::atomic::AtomicPtr};

use windows::{
    core::{s, PCSTR},
    Win32::{
        Foundation::HWND,
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE},
    },
};

use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};

type MessageBoxASig = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;

pub struct MessageBoxAFunc;
impl MessageBoxAFunc {
    pub const NAME: &'static str = "MessageBoxAFunc";
}
impl HookableFunc for MessageBoxAFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("user32.dll", "MessageBoxA").unwrap(),
            message_box_a_proxy_func as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            MessageBoxAFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() {
        unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };
    }
}

#[no_mangle]
pub extern "system" fn message_box_a_proxy_func(
    hwnd: HWND,
    lptext: PCSTR,
    lpcaption: PCSTR,
    utype: u32,
) -> i32 {
    println!("HOOKED");
    println!("  hwnd: {hwnd:?}");
    println!("  lptext: '{}'", unsafe { lptext.to_string().unwrap() });
    println!("  lpcaption: '{}'", unsafe {
        lpcaption.to_string().unwrap()
    });
    println!("  utype: {:?}", utype);

    // Call original function
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("MessageBoxAFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), MessageBoxASig>(p) };

    let new_text = s!("gotcha bitch");

    unsafe { orig(hwnd, new_text, lpcaption, utype) }
}
