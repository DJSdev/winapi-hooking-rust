use iced_x86::{
    code_asm::*, BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, Register,
};
use std::{cmp, ffi::c_void, ptr};
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    },
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    Threading::GetCurrentProcess,
};

use crate::util::HookError;

#[derive(Debug, Clone)]
pub struct StolenBytes {
    pub instrs: Vec<Instruction>,
    pub num_bytes: usize,
}
impl StolenBytes {
    fn new(instrs: Vec<Instruction>, num_bytes: usize) -> Self {
        Self { instrs, num_bytes }
    }
}

#[derive(Debug)]
pub struct TrampolineMem {
    pub addr: *mut c_void,
    pub size: Option<u64>,
}
impl TrampolineMem {
    fn new(addr: *mut c_void, size: Option<u64>) -> Self {
        Self { addr, size }
    }
}

type RelayFunction = Vec<Instruction>;

/// Private function used by `build_trampoline()` to create the jmp
/// back to the original function
///
/// Copy the first MIN_SIZE bytes from the prologue of a function
/// Decode the bytes using iced_x86 disassembler into Instructions
///
///  # Arguments
///
/// * `func_addr`: Address of function to hook (from `GetProcAddress()`)
///
/// # Returns
///
/// * `StolenBytes`: struct containing the copied x86 instructions and size in bytes
///
/// # Examples
///
/// ```
/// let func_addr = find_func_addr("user32.dll", "GetCursorPos").unwrap();
/// let stolen_bytes = steal_bytes(func_addr).unwrap();
/// ```
pub fn steal_bytes(func_addr: *const c_void, min_bytes: usize) -> StolenBytes {
    // Arbitrary amount of bytes to read to ensure we read enough
    const N_BYTES: usize = 50;
    let mut saved_buffer = vec![0; N_BYTES];

    // Get the prologue of the function
    unsafe {
        ptr::copy_nonoverlapping(func_addr, saved_buffer.as_mut_ptr() as *mut c_void, N_BYTES)
    };

    let p_saved_buffer = saved_buffer.as_mut_ptr();

    let code = unsafe { std::slice::from_raw_parts(p_saved_buffer, N_BYTES) };

    // Need to use `.with_ip()` to be able to re-encode relative addresses
    let mut dec = Decoder::with_ip(64, code, func_addr as u64, DecoderOptions::NONE);

    let mut read = 0usize;
    let mut instructions: Vec<Instruction> = Vec::new();

    while read < min_bytes {
        let instr = dec.decode();

        if instr.is_invalid() {
            break;
        }

        read += instr.len();
        instructions.push(instr);
    }

    StolenBytes::new(instructions, read)
}

/// Alloc a trampoline in memory near the original function.
///
/// Placing it near the original function is important as x86
/// will not allow `jmp`s further than 2GB
///
/// # Arguments
///
/// * `func_addr`: Address of function to hook (from `GetProcAddress()`)
///
/// # Returns
///
/// * `Ok(TrampolineMem)`: struct containing the trampoline memory address and size
/// * `Err(HookError)`: if the trampoline cannot be allocated
///
/// # Examples
///
/// ```
/// let func_addr = find_func_addr("user32.dll", "GetCursorPos").unwrap();
/// let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();
/// ```
pub fn alloc_trampoline_mem_near_address(
    func_addr: *const c_void,
) -> Result<TrampolineMem, HookError> {
    let mut info: SYSTEM_INFO = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    let size: u64 = info.dwPageSize.into();

    let two_gb_window = 0x7FFFFF00; // 2,147,483,392 bytes

    let start_address = func_addr as u64 & !(size - 1);

    let min_address = cmp::min(
        start_address - two_gb_window,
        info.lpMinimumApplicationAddress as u64,
    );
    let max_address = cmp::max(
        start_address + two_gb_window,
        info.lpMaximumApplicationAddress as u64,
    );

    let start_page = start_address - (start_address % size);

    let mut offset = 1;
    loop {
        let byte_offset = offset * size;

        let high_addr = start_page + byte_offset;
        let low_addr = start_page.saturating_sub(byte_offset);

        let needs_exit = high_addr > max_address && low_addr < min_address;

        if high_addr < max_address {
            let addr = unsafe {
                VirtualAlloc(
                    Some(high_addr as *const c_void),
                    size as usize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE, // Start with ReadWrite to not be too obvious, change to Execute later
                )
            };
            if !addr.is_null() {
                return Ok(TrampolineMem::new(addr, Some(size)));
            }
        }

        if low_addr > min_address {
            let addr = unsafe {
                VirtualAlloc(
                    Some(low_addr as *const c_void),
                    size as usize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE, // Start with ReadWrite to not be too obvious, change to Execute later
                )
            };
            if !addr.is_null() {
                return Ok(TrampolineMem::new(addr, Some(size)));
            }
        }

        offset += 1;

        if needs_exit {
            return Err(HookError::Alloc(format!(
                "Unable to allocate memory near address {func_addr:?}"
            )));
        }
    }
}

/// Adds instructions to the trampoline allocated by the caller
///
/// Steal bytes from the original function, then append a jump to
/// the end get back to the original function
///
/// # Arguments
///
/// * `func_addr`: Address of function to hook (from `GetProcAddress()`)
/// * `dst_hook_mem`: &mut TrampolineMem
///
/// # Examples
///
/// ```
/// let func_addr = find_func_addr("user32.dll", "GetCursorPos").unwrap();
/// let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();
///
/// build_trampoline(func_addr, &mut trampoline);
/// ```
pub fn build_trampoline(
    func_addr: *const c_void,
    stolen_bytes: &StolenBytes,
    dst_hook_mem: &mut TrampolineMem,
) {
    // Take the original function address
    // add the number of stolen bytes to the pointer
    // that will be where we need to "trampoline" back to
    let jmp_back_addr = unsafe { func_addr.add(stolen_bytes.num_bytes) };

    let mut instructions = stolen_bytes.instrs.clone();

    for i in &mut instructions {
        if i.code() == Code::Int3 {
            i.set_code(Code::Nop_rm16);
        }
    }

    // Append `jmp` to end of trampoline to "bounce" back to the original function
    //
    // ASM:
    //     mov r10, addr
    //     jmp r10
    instructions.push(
        Instruction::with2(Code::Mov_r64_imm64, Register::R10, jmp_back_addr as u64).unwrap(),
    );
    instructions.push(Instruction::with1(Code::Jmp_rm64, Register::R10).unwrap());

    // The block encoder should auto-magically fix any RIP relative addressing
    let encoded_instrs = BlockEncoder::encode(
        64,
        InstructionBlock::new(&instructions, dst_hook_mem.addr as u64),
        BlockEncoderOptions::NONE,
    )
    .unwrap();

    println!(
        "Wrapping add func {:x?}",
        func_addr.wrapping_add(stolen_bytes.num_bytes)
    );
    println!("RIP: {:x?}", encoded_instrs.rip);
    println!(
        "Dst Hook Trampoline: dis -s {:x?} -c 10 -b",
        dst_hook_mem.addr
    );

    unsafe {
        std::ptr::copy_nonoverlapping(
            encoded_instrs.code_buffer.as_ptr(),
            dst_hook_mem.addr as *mut u8,
            encoded_instrs.code_buffer.len(),
        )
    };

    // Change protection level on trampoline to allow execution
    unsafe {
        VirtualProtect(
            dst_hook_mem.addr,
            encoded_instrs.code_buffer.len(),
            PAGE_EXECUTE_READWRITE, // Set to ReadWriteExecute
            &mut PAGE_PROTECTION_FLAGS::default(),
        )
        .expect("Unable to change access permissions on Destination Hook memory")
    };

    dst_hook_mem.size = Some(encoded_instrs.code_buffer.len() as u64);
}

/// Overwrites a given function with a jmp instr to jump to the intended proxy function
///
/// # Arguments
///
/// * `func_addr`: Address of function to hook (from `GetProcAddress()`)
/// * `proxy_func`: Address to overwrite the original function with
pub fn install_hook(
    relay_function: RelayFunction,
    func_addr: *const c_void,
    stolen_bytes: StolenBytes,
) {
    println!("\nInstalling hook...");

    println!("target func addr {func_addr:x?}");

    let encoded_instrs = encode_relay_function(&relay_function, func_addr);

    // 1) Change the protection level of the memory to be writable
    let mut original_protect = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtect(
            func_addr,
            encoded_instrs.len(),
            PAGE_READWRITE,
            &mut original_protect,
        )
        .expect("Unable to change access permissions to memory")
    };

    // 2) Overwrite the function prologue
    unsafe {
        std::ptr::copy_nonoverlapping(
            encoded_instrs.as_ptr(),
            func_addr as *mut u8,
            stolen_bytes.num_bytes,
        )
    };

    // 3) Reapply the original protections
    unsafe {
        VirtualProtect(
            func_addr,
            encoded_instrs.len(),
            original_protect,
            &mut PAGE_PROTECTION_FLAGS::default(),
        )
        .expect("Unable to reassign original memory access permissions")
    };

    let _ = unsafe { FlushInstructionCache(GetCurrentProcess(), None, 0) };
}

pub fn encode_relay_function(relay_func: &[Instruction], func_addr: *const c_void) -> Vec<u8> {
    BlockEncoder::encode(
        64,
        InstructionBlock::new(relay_func, func_addr as u64),
        BlockEncoderOptions::NONE,
    )
    .unwrap()
    .code_buffer
}

pub fn byte_len_instructions(relay_func: &[Instruction]) -> usize {
    let placeholder_addr = 0u64;

    BlockEncoder::encode(
        64,
        InstructionBlock::new(relay_func, placeholder_addr),
        BlockEncoderOptions::NONE,
    )
    .unwrap()
    .code_buffer
    .len()
}

/// Create the initial relay function
///
/// This may not be the correct size to replace a function prologue.
/// It may split bytes. So find the length of the valid instructions
/// in the prologue, then use `pad_relay_function()` to pad out with
/// valid instructions
///
/// # Returns
///
/// - `RelayFunction` A vec of instructions representing the following
///
/// ```asm
/// mov r10, proxy_func
/// jmp r10
/// ```
pub fn init_relay_function(proxy_func: *const c_void) -> RelayFunction {
    let mut a = CodeAssembler::new(64).unwrap();

    a.mov(r10, proxy_func as u64).unwrap();
    a.jmp(r10).unwrap();

    a.instructions().to_vec()
}

/// Pad the relay function with `nops` up to a certain bytes length
///
/// # Arguments
///
/// * `relay_func` - Vec of instructions to append to
/// * `n_nops` - number of nops in order to add to function
///
/// # Returns
///
/// - `RelayFunction` A vec of instructions representing the following with N nops appended
///
/// ```asm
/// mov r10, proxy_func
/// jmp r10
/// nop
/// ...
/// ```
pub fn pad_relay_function(mut relay_func: RelayFunction, n_nops: usize) -> RelayFunction {
    let mut a = CodeAssembler::new(64).unwrap();

    for _ in 0..n_nops {
        a.nop().unwrap();
    }

    a.instructions()
        .iter()
        .for_each(|inst| relay_func.push(*inst));

    relay_func
}
