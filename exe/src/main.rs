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

use crate::{funcs::message_box_a::MessageBoxAFunc, instructions::{
    alloc_trampoline_mem_near_address, build_trampoline, byte_len_instructions,
    init_relay_function, install_hook, pad_relay_function, steal_bytes,
}};

use crate::funcs::HookableFunc;

type MessageBoxASig = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
type GetCursorPosSig = unsafe extern "system" fn(*mut POINT) -> BOOL;
type GetClipboardDataSig = unsafe extern "system" fn(u32) -> HANDLE;
type SleepSig = unsafe extern "system" fn(u32);
type IsDebuggerPresentSig = unsafe extern "system" fn() -> BOOL;
type GetSystemTimeAsFileTimeSig = unsafe extern "system" fn(*mut c_void);
type ExitProcessSig = unsafe extern "system" fn(u32);
type CreateFileWSig =
    unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, HANDLE) -> HANDLE;
type VirtualAllocExSig =
    unsafe extern "system" fn(HANDLE, *const c_void, usize, u32, u32) -> *mut c_void;
type NtQuerySystemInformationSig =
    unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type NtOpenProcessSig =
    unsafe extern "system" fn(*mut HANDLE, u32, *mut c_void, *mut c_void) -> i32;

// Global pointer to the trampoline code
// static P_TRAMPOLINE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

pub static P_TRAMPOLINE: LazyLock<Mutex<HashMap<&str, AtomicPtr<()>>>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    Mutex::new(m)
});

enum TestFuncs {
    MessageBox,
    GetCursorPos,
    GetClipboardData,
    Sleep,
    IsDebuggerPresent,
    GetSystemTimeAsFileTime,
    ExitProcess,
    CreateFileW,
    VirtualAllocEx,
    NtQuerySystemInformation,
    NtOpenProcess,
}

fn main() {
    // Change this here to test other functions
    // let test_func = TestFuncs::VirtualAllocEx;

    // let (func_addr, proxy_func) = match test_func {
    //     TestFuncs::MessageBox => (
    //         find_func_addr("user32.dll", "MessageBoxA").unwrap(),
    //         message_box_a_proxy_func as *const c_void,
    //     ),
    //     TestFuncs::GetCursorPos => (
    //         find_func_addr("user32.dll", "GetCursorPos").unwrap(),
    //         get_cursor_pos_proxy as *const c_void,
    //     ),
    //     TestFuncs::GetClipboardData => (
    //         find_func_addr("user32.dll", "GetClipboardData").unwrap(),
    //         get_clipboard_data_proxy as *const c_void,
    //     ),
    //     TestFuncs::Sleep => (
    //         find_func_addr("Kernel32.dll", "Sleep").unwrap(),
    //         sleep_proxy as *const c_void,
    //     ),
    //     TestFuncs::IsDebuggerPresent => (
    //         find_func_addr("Kernel32.dll", "IsDebuggerPresent").unwrap(),
    //         is_debugger_present_proxy as *const c_void,
    //     ),
    //     TestFuncs::GetSystemTimeAsFileTime => (
    //         find_func_addr("Kernel32.dll", "GetSystemTimeAsFileTime").unwrap(),
    //         get_system_time_as_file_time_proxy as *const c_void,
    //     ),
    //     TestFuncs::ExitProcess => (
    //         find_func_addr("Kernel32.dll", "ExitProcess").unwrap(),
    //         exit_process_proxy as *const c_void,
    //     ),
    //     TestFuncs::CreateFileW => (
    //         find_func_addr("Kernel32.dll", "CreateFileW").unwrap(),
    //         create_file_w_proxy as *const c_void,
    //     ),
    //     TestFuncs::VirtualAllocEx => (
    //         find_func_addr("Kernel32.dll", "VirtualAllocEx").unwrap(),
    //         virtual_alloc_ex_proxy as *const c_void,
    //     ),
    //     TestFuncs::NtQuerySystemInformation => (
    //         find_func_addr("ntdll.dll", "NtQuerySystemInformation").unwrap(),
    //         nt_query_system_information_proxy as *const c_void,
    //     ),
    //     TestFuncs::NtOpenProcess => (
    //         find_func_addr("ntdll.dll", "NtOpenProcess").unwrap(),
    //         nt_open_process_proxy as *const c_void,
    //     ),
    // };

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

    // match test_func {
    //     TestFuncs::MessageBox => {
    //         unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };
    //     }
    //     TestFuncs::GetCursorPos => {
    //         let mut point = POINT::default();
    //         unsafe { GetCursorPos(&mut point).unwrap() };
    //         println!("{point:?}");
    //     }
    //     TestFuncs::GetClipboardData => {
    //         let c_data = unsafe { GetClipboardData(0) };
    //         match c_data {
    //             Ok(data) => println!("{:?}", data),
    //             Err(err) => {
    //                 let last_err = unsafe { GetLastError() };
    //                 println!("{last_err:?} {err}");
    //             }
    //         }
    //     }
    //     TestFuncs::Sleep => {
    //         println!("eepy time");
    //         unsafe { Sleep(5000) };
    //         println!("waky waky");
    //     }
    //     TestFuncs::IsDebuggerPresent => {
    //         let func =
    //             unsafe { std::mem::transmute::<*const c_void, IsDebuggerPresentSig>(func_addr) };
    //         println!("IsDebuggerPresent: {:?}", unsafe { func() });
    //     }
    //     TestFuncs::GetSystemTimeAsFileTime => {
    //         let func = unsafe {
    //             std::mem::transmute::<*const c_void, GetSystemTimeAsFileTimeSig>(func_addr)
    //         };
    //         let mut file_time = [0u8; 8];
    //         unsafe { func(file_time.as_mut_ptr() as *mut c_void) };
    //         println!("GetSystemTimeAsFileTime: {:?}", file_time);
    //     }
    //     TestFuncs::ExitProcess => {
    //         let func = unsafe { std::mem::transmute::<*const c_void, ExitProcessSig>(func_addr) };
    //         unsafe { func(0) };
    //     }
    //     TestFuncs::CreateFileW => {
    //         let func = unsafe { std::mem::transmute::<*const c_void, CreateFileWSig>(func_addr) };
    //         let path: Vec<u16> = "C:\\Windows\\System32\\notepad.exe\0"
    //             .encode_utf16()
    //             .collect();
    //         let handle = unsafe {
    //             func(
    //                 path.as_ptr(),
    //                 0x80000000,
    //                 1,
    //                 std::ptr::null_mut(),
    //                 3,
    //                 0x80,
    //                 HANDLE::default(),
    //             )
    //         };
    //         println!("CreateFileW handle: {:?}", handle);
    //     }
    //     TestFuncs::VirtualAllocEx => {
    //         let func =
    //             unsafe { std::mem::transmute::<*const c_void, VirtualAllocExSig>(func_addr) };
    //         let current_process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    //         let ptr = unsafe {
    //             func(
    //                 current_process,
    //                 std::ptr::null(),
    //                 0x1000,
    //                 0x1000 | 0x2000,
    //                 0x40,
    //             )
    //         };
    //         println!("VirtualAllocEx allocated: {:?}", ptr);
    //     }
    //     TestFuncs::NtQuerySystemInformation => {
    //         let func = unsafe {
    //             std::mem::transmute::<*const c_void, NtQuerySystemInformationSig>(func_addr)
    //         };
    //         let mut ret_len = 0u32;
    //         let status = unsafe { func(0, std::ptr::null_mut(), 0, &mut ret_len) };
    //         println!(
    //             "NtQuerySystemInformation status: {:x}, len: {}",
    //             status, ret_len
    //         );
    //     }
    //     TestFuncs::NtOpenProcess => {
    //         let func = unsafe { std::mem::transmute::<*const c_void, NtOpenProcessSig>(func_addr) };
    //         let mut handle = HANDLE::default();
    //         let status =
    //             unsafe { func(&mut handle, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    //         println!("NtOpenProcess status: {:x}, handle: {:?}", status, handle);
    //     }
    // }

    println!("Done");
}

// #[no_mangle]
// pub extern "system" fn message_box_a_proxy_func(
//     hwnd: HWND,
//     lptext: PCSTR,
//     lpcaption: PCSTR,
//     utype: u32,
// ) -> i32 {
//     println!("HOOKED");
//     println!("  hwnd: {hwnd:?}");
//     println!("  lptext: '{}'", unsafe { lptext.to_string().unwrap() });
//     println!("  lpcaption: '{}'", unsafe {
//         lpcaption.to_string().unwrap()
//     });
//     println!("  utype: {:?}", utype);

//     // Call original function
//     let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), MessageBoxASig>(p) };

//     let new_text = s!("gotcha bitch");

//     unsafe { orig(hwnd, new_text, lpcaption, utype) }
// }

// #[no_mangle]
// pub extern "system" fn get_cursor_pos_proxy(lppoint: *mut POINT) -> BOOL {
//     println!("HOOKED");
//     println!("  lppoint: {lppoint:?}");

//     // Call original function
//     let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), GetCursorPosSig>(p) };

//     let res = unsafe { orig(lppoint) };

//     unsafe {
//         if !lppoint.is_null() {
//             (*lppoint).x = 69;
//             (*lppoint).y = 420;
//         }
//     }

//     res
// }

// #[no_mangle]
// pub extern "system" fn get_clipboard_data_proxy(u_format: u32) -> HANDLE {
//     println!("HOOKED");
//     println!("  u_format: {u_format:?}");

//     // Call original function
//     let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), GetClipboardDataSig>(p) };

//     unsafe { orig(u_format) }
// }

// #[no_mangle]
// pub extern "system" fn sleep_proxy(ms: u32) {
//     println!("HOOKED");
//     println!("  Milliseconds: {ms:?}");

//     // Call original function
//     let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), SleepSig>(p) };

//     println!("Actually sleeping for 2 seconds");
//     unsafe { orig(2) };
// }

// #[no_mangle]
// pub extern "system" fn is_debugger_present_proxy() -> BOOL {
//     println!("HOOKED IsDebuggerPresent");
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), IsDebuggerPresentSig>(p) };
//     unsafe { orig() }
// }

// #[no_mangle]
// pub extern "system" fn get_system_time_as_file_time_proxy(system_time_as_file_time: *mut c_void) {
//     println!("HOOKED GetSystemTimeAsFileTime");
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), GetSystemTimeAsFileTimeSig>(p) };
//     unsafe { orig(system_time_as_file_time) }
// }

// #[no_mangle]
// pub extern "system" fn exit_process_proxy(exit_code: u32) {
//     println!("HOOKED ExitProcess: code {}", exit_code);
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), ExitProcessSig>(p) };
//     unsafe { orig(exit_code) }
// }

// #[no_mangle]
// pub extern "system" fn create_file_w_proxy(
//     lpfilename: *const u16,
//     dwdesiredaccess: u32,
//     dwsharemode: u32,
//     lpsecurityattributes: *mut c_void,
//     dwcreationdisposition: u32,
//     dwflagsandattributes: u32,
//     htemplatefile: HANDLE,
// ) -> HANDLE {
//     println!("HOOKED CreateFileW: access {:x}", dwdesiredaccess);
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), CreateFileWSig>(p) };
//     unsafe {
//         orig(
//             lpfilename,
//             dwdesiredaccess,
//             dwsharemode,
//             lpsecurityattributes,
//             dwcreationdisposition,
//             dwflagsandattributes,
//             htemplatefile,
//         )
//     }
// }

// #[no_mangle]
// pub extern "system" fn virtual_alloc_ex_proxy(
//     hprocess: HANDLE,
//     lpaddress: *const c_void,
//     dwsize: usize,
//     flallocationtype: u32,
//     flprotect: u32,
// ) -> *mut c_void {
//     println!("HOOKED VirtualAllocEx: size 0x{:x}", dwsize);
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), VirtualAllocExSig>(p) };
//     unsafe { orig(hprocess, lpaddress, dwsize, flallocationtype, flprotect) }
// }

// #[no_mangle]
// pub extern "system" fn nt_query_system_information_proxy(
//     systeminformationclass: u32,
//     systeminformation: *mut c_void,
//     systeminformationlength: u32,
//     returnlength: *mut u32,
// ) -> i32 {
//     println!(
//         "HOOKED NtQuerySystemInformation: class {}",
//         systeminformationclass
//     );
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), NtQuerySystemInformationSig>(p) };
//     unsafe {
//         orig(
//             systeminformationclass,
//             systeminformation,
//             systeminformationlength,
//             returnlength,
//         )
//     }
// }

// #[no_mangle]
// pub extern "system" fn nt_open_process_proxy(
//     processhandle: *mut HANDLE,
//     desiredaccess: u32,
//     objectattributes: *mut c_void,
//     clientid: *mut c_void,
// ) -> i32 {
//     println!("HOOKED NtOpenProcess: access 0x{:x}", desiredaccess);
//     let p = P_TRAMPOLINE.load(Ordering::Acquire);
//     let orig = unsafe { std::mem::transmute::<*mut (), NtOpenProcessSig>(p) };
//     unsafe { orig(processhandle, desiredaccess, objectattributes, clientid) }
// }
