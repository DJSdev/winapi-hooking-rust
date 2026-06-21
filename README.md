# Win32 Function Hooking in Rust

This project demonstrates how to hook a Win32 API function (such as `MessageBoxA`) in Rust by redirecting execution to a proxy function before invoking the original function.

## How it Works

The hooking process consists of the following steps:

1. **init_relay_function()**: Creates a relay function containing instructions to jump to the proxy function (`mov r10, <proxy_addr>; jmp r10`).
1. **byte_len_instructions()**: Determines the byte length of the relay function (generally 13 bytes on x64).
1. **steal_bytes()**: Copies instructions from the target function's prologue. It decodes instructions until the total size is greater than or equal to the relay function's length. This prevents splitting an instruction in half.
1. **pad_relay_function()**: If the stolen bytes exceed the initial relay function length, the relay function is padded with `nop` instructions so its final size matches the exact number of stolen bytes.
1. **alloc_trampoline_mem_near_address()**: Allocates executable memory near the target function's address (within a 2 GB window). This range limit is required for x86/x64 because any RIP-relative instructions inside the stolen bytes use 32-bit signed offsets and must remain close to their original target addresses.
1. **build_trampoline()**: Copies the stolen bytes into the allocated trampoline memory and appends an absolute jump back to the remainder of the target function (`mov r10, <jmp_back_addr>; jmp r10`). The `iced-x86` library is used to re-encode and adjust RIP-relative displacement offsets.
1. **set_p_trampoline()**: Adds the trampoline to a globally tracked list of proxied functions.
1. **install_hook()**: Changes target memory permissions to write, overwrites the prologue of the target function with the padded relay function, restores permissions, and flushes the instruction cache.
1. **invoke()**: Call the original function (with this running program) to verify hooking and proxy-ing

All hooking logic is implemented in [exe/src/instructions.rs](exe/src/instructions.rs) and showcased in [exe/src/main.rs](exe/src/main.rs).

## Build

To build the entire workspace (both the executable and the DLL):

```bash
cargo build
```

## Run

The `rs-test` executable includes a CLI to specify which Win32 API function you want to hook and test. By default, it hooks `MessageBoxA`.

To run the program, use:

```bash
cargo run -p rs-test -- --target <TARGET>
```

### Available Targets

The following functions are currently supported for hooking tests:
- `message-box-a` (default)
- `get-cursor-pos`
- `get-clipboard-data`
- `sleep`
- `is-debugger-present`
- `get-system-time-as-file-time`
- `exit-process`
- `create-file-w`
- `virtual-alloc-ex`
- `nt-query-system-information`
- `nt-open-process`

### Examples

```bash
# Run with the default target (MessageBoxA)
cargo run -p rs-test

# Run the GetCursorPos hook test
cargo run -p rs-test -- --target get-cursor-pos

# Run the Sleep hook test
cargo run -p rs-test -- --target sleep
```
