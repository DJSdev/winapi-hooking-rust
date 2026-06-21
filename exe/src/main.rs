mod funcs;
mod instructions;
mod util;

use std::{
    collections::HashMap,
    ffi::c_void,
    hash::Hash,
    sync::{
        atomic::{AtomicPtr, Ordering},
        LazyLock, Mutex,
    },
};

use util::find_func_addr;
use windows::Win32::Foundation::GetLastError;
#[allow(unused_imports)]
use windows::{
    core::{s, BOOL, PCSTR},
    Win32::{
        Foundation::{HANDLE, HWND, POINT},
        System::DataExchange::GetClipboardData,
        System::Threading::Sleep,
        UI::WindowsAndMessaging::{GetCursorPos, MessageBoxA, MESSAGEBOX_STYLE},
    },
};

use crate::{
    funcs::message_box_a::MessageBoxAFunc,
    instructions::{
        alloc_trampoline_mem_near_address, build_trampoline, byte_len_instructions,
        init_relay_function, install_hook, pad_relay_function, steal_bytes,
    },
};

use crate::funcs::HookableFunc;

pub static P_TRAMPOLINE: LazyLock<Mutex<HashMap<&str, AtomicPtr<()>>>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    Mutex::new(m)
});

fn main() {
    let (func_addr, proxy_func) = MessageBoxAFunc::get_addr_and_proxy();

    // Use for disassembling
    println!("Actual Func: dis -s {func_addr:x?} -c 10 -b ");

    // 1) Create the relay function that will overwrite the MessageBoxA function prologue
    let mut relay_func = init_relay_function(proxy_func);

    // 2) Get the length of the relay function in bytes
    let relay_func_len = byte_len_instructions(&relay_func);
    println!("Relay function length in bytes {relay_func_len}");

    // 3) Steal bytes from the prologue of the function up to the length of the relay_function
    let stolen_bytes = steal_bytes(func_addr, relay_func_len);
    // println!(
    //     "Stolen bytes {:?}",
    //     byte_len_instructions(&stolen_bytes.instrs)
    // );
    println!(
        "Need {:?} more byte(s)",
        stolen_bytes.num_bytes - relay_func_len
    );

    // 4) Re-encode the relay function with no-ops
    //   * The relay function likely splits an instruction and breaks shit, so we need to ensure
    //     that the relay function is the same length as the number of bytes we stole
    if stolen_bytes.num_bytes > relay_func_len {
        relay_func = pad_relay_function(relay_func, stolen_bytes.num_bytes - relay_func_len);
    }

    // 5) Alloc memory near the original function for the trampoline
    let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();

    // 6) Build the trampoline
    build_trampoline(func_addr, &stolen_bytes, &mut trampoline);
    println!("Trampoline size: {}", trampoline.size.unwrap());
    println!("Trampoline addr: {:x?}", trampoline.addr);

    // 7) Store a reference to the trampoline addr for the proxy to callback
    // TODO: Fix RIP relative instructions on trampoline to ensure they point to correct memory
    //     1) Disassemble actual function: dis -s 0x7ffa4f4c8b70 -c 10 -b
    //     2) Disassemble actual function after copying: dis -s 0x7ffa4f4c8b70 -c 10 -b
    //     3) Disable trampoline function: dis -s 0x7ffa4f440000 -c 10 -b

    // Need to calc 0x7ffe4fc5d22e + 0x4362a = 0x7ffe4fca0858
    MessageBoxAFunc::set_p_trampoline(trampoline);
    // P_TRAMPOLINE.store(trampoline.addr as *mut (), Ordering::Release);

    // 8) Install the hook
    install_hook(relay_func, func_addr, stolen_bytes);

    MessageBoxAFunc::invoke();
}
