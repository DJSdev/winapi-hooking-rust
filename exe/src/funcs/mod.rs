pub mod message_box_a;

use std::ffi::c_void;

use crate::instructions::TrampolineMem;

pub trait HookableFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void);
    fn invoke() -> ();
    fn set_p_trampoline(trampoline: TrampolineMem);
}
