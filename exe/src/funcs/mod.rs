pub mod create_file_w;
pub mod exit_process;
pub mod get_clipboard_data;
pub mod get_cursor_pos;
pub mod get_system_time_as_file_time;
pub mod is_debugger_present;
pub mod message_box_a;
pub mod nt_open_process;
pub mod nt_query_system_information;
pub mod sleep;
pub mod virtual_alloc_ex;

use std::ffi::c_void;

use crate::instructions::TrampolineMem;

pub trait HookableFunc {
    fn get_addr_and_proxy() -> (*const c_void, *const c_void);
    fn invoke();
    fn set_p_trampoline(trampoline: TrampolineMem);
}
