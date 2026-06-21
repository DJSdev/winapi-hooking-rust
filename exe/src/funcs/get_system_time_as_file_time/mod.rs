use crate::{funcs::HookableFunc, util::find_func_addr, P_TRAMPOLINE};
use std::{ffi::c_void, sync::atomic::AtomicPtr};

type GetSystemTimeAsFileTimeSig = unsafe extern "system" fn(*mut c_void);

pub struct GetSystemTimeAsFileTimeFunc;
impl GetSystemTimeAsFileTimeFunc {
    pub const NAME: &'static str = "GetSystemTimeAsFileTimeFunc";
}
impl HookableFunc for GetSystemTimeAsFileTimeFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void) {
        (
            find_func_addr("Kernel32.dll", "GetSystemTimeAsFileTime").unwrap(),
            get_system_time_as_file_time_proxy as *const c_void,
        )
    }

    fn set_p_trampoline(trampoline: crate::instructions::TrampolineMem) {
        P_TRAMPOLINE.lock().unwrap().insert(
            GetSystemTimeAsFileTimeFunc::NAME,
            AtomicPtr::new(trampoline.addr as *mut ()),
        );
    }

    fn invoke() -> () {
        let (func_addr, _) = Self::get_addr_and_proxy();
        let func =
            unsafe { std::mem::transmute::<*const c_void, GetSystemTimeAsFileTimeSig>(func_addr) };
        let mut file_time = [0u8; 8];
        unsafe { func(file_time.as_mut_ptr() as *mut c_void) };
        println!("GetSystemTimeAsFileTime: {:?}", file_time);
    }
}

#[no_mangle]
pub extern "system" fn get_system_time_as_file_time_proxy(system_time_as_file_time: *mut c_void) {
    println!("HOOKED GetSystemTimeAsFileTime");
    let p = P_TRAMPOLINE
        .lock()
        .unwrap()
        .get("GetSystemTimeAsFileTimeFunc")
        .unwrap()
        .load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), GetSystemTimeAsFileTimeSig>(p) };
    unsafe { orig(system_time_as_file_time) }
}
