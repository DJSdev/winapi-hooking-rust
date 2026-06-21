use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};

type NtQuerySystemInformationSig =
    unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

pub struct NtQuerySystemInformationFunc;
impl NtQuerySystemInformationFunc {
    pub const NAME: &'static str = "NtQuerySystemInformationFunc";
}
impl HookableFunc for NtQuerySystemInformationFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("ntdll.dll", "NtQuerySystemInformation").unwrap(),
            nt_query_system_information_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            NtQuerySystemInformationFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() -> () {
        let (func_addr, _) = Self::get_addr_and_proxy();
        let func =
            unsafe { std::mem::transmute::<*const c_void, NtQuerySystemInformationSig>(func_addr) };
        let mut ret_len = 0u32;
        let status = unsafe { func(0, std::ptr::null_mut(), 0, &mut ret_len) };
        println!(
            "NtQuerySystemInformation status: {:x}, len: {}",
            status, ret_len
        );
    }
}

#[no_mangle]
pub extern "system" fn nt_query_system_information_proxy(
    systeminformationclass: u32,
    systeminformation: *mut c_void,
    systeminformationlength: u32,
    returnlength: *mut u32,
) -> i32 {
    println!(
        "HOOKED NtQuerySystemInformation: class {}",
        systeminformationclass
    );
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("NtQuerySystemInformationFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), NtQuerySystemInformationSig>(p) };
    unsafe {
        orig(
            systeminformationclass,
            systeminformation,
            systeminformationlength,
            returnlength,
        )
    }
}
