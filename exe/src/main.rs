mod cli;
mod funcs;
mod instructions;
mod util;

use std::{
    collections::HashMap,
    sync::{atomic::AtomicPtr, LazyLock, Mutex},
};

use clap::Parser;
use cli::{Args, HookTarget};

use crate::{
    funcs::message_box_a::MessageBoxAFunc,
    instructions::{
        alloc_trampoline_mem_near_address, build_trampoline, byte_len_instructions,
        init_relay_function, install_hook, pad_relay_function, steal_bytes,
    },
};

use crate::funcs::HookableFunc;

pub static P_TRAMPOLINE: LazyLock<Mutex<HashMap<&str, AtomicPtr<()>>>> = LazyLock::new(|| {
    let m = HashMap::new();
    Mutex::new(m)
});

macro_rules! hook_and_test {
    ($type:ty) => {{
        let (func_addr, proxy_func) = <$type>::get_addr_and_proxy();

        println!("Actual Func: dis -s {:x?} -c 10 -b ", func_addr);

        let mut relay_func = init_relay_function(proxy_func);
        let relay_func_len = byte_len_instructions(&relay_func);
        println!("Relay function length in bytes {}", relay_func_len);

        let stolen_bytes = steal_bytes(func_addr, relay_func_len);
        println!(
            "Need {:?} more byte(s)",
            stolen_bytes.num_bytes - relay_func_len
        );

        if stolen_bytes.num_bytes > relay_func_len {
            relay_func = pad_relay_function(relay_func, stolen_bytes.num_bytes - relay_func_len);
        }

        let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();
        build_trampoline(func_addr, &stolen_bytes, &mut trampoline);

        println!("Trampoline size: {}", trampoline.size.unwrap());
        println!("Trampoline addr: {:x?}", trampoline.addr);

        <$type>::set_p_trampoline(trampoline);
        install_hook(relay_func, func_addr, stolen_bytes);
        <$type>::invoke();
    }};
}

fn main() {
    let args = Args::parse();

    match args.target {
        HookTarget::MessageBoxA => hook_and_test!(MessageBoxAFunc),
        HookTarget::GetCursorPos => hook_and_test!(funcs::get_cursor_pos::GetCursorPosFunc),
        HookTarget::GetClipboardData => {
            hook_and_test!(funcs::get_clipboard_data::GetClipboardDataFunc)
        }
        HookTarget::Sleep => hook_and_test!(funcs::sleep::SleepFunc),
        HookTarget::IsDebuggerPresent => {
            hook_and_test!(funcs::is_debugger_present::IsDebuggerPresentFunc)
        }
        HookTarget::GetSystemTimeAsFileTime => {
            hook_and_test!(funcs::get_system_time_as_file_time::GetSystemTimeAsFileTimeFunc)
        }
        HookTarget::ExitProcess => hook_and_test!(funcs::exit_process::ExitProcessFunc),
        HookTarget::CreateFileW => hook_and_test!(funcs::create_file_w::CreateFileWFunc),
        HookTarget::VirtualAllocEx => hook_and_test!(funcs::virtual_alloc_ex::VirtualAllocExFunc),
        HookTarget::NtQuerySystemInformation => {
            hook_and_test!(funcs::nt_query_system_information::NtQuerySystemInformationFunc)
        }
        HookTarget::NtOpenProcess => hook_and_test!(funcs::nt_open_process::NtOpenProcessFunc),
    }
}
