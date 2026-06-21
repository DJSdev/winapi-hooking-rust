# Win32 Function Hooking in Rust

This project demonstrates how to hook a Win32 API function (such as `MessageBoxA`) in Rust by redirecting execution to a proxy function before invoking the original function.

## How it Works

The hooking process consists of the following steps:

1. **Initialize Relay Function**: Creates a relay function containing instructions to jump to the proxy function (`mov r10, <proxy_addr>; jmp r10`).
2. **Calculate Relay Length**: Determines the byte length of the relay function (13 bytes on x64).
3. **Steal Bytes**: Copies instructions from the target function's prologue. It decodes instructions until the total size is greater than or equal to the relay function's length. This prevents splitting an instruction in half.
4. **Pad Relay Function**: If the stolen bytes exceed the initial relay function length, the relay function is padded with `nop` instructions so its final size matches the exact number of stolen bytes.
5. **Allocate Trampoline Memory**: Allocates executable memory near the target function's address (within a 2 GB window). This range limit is required for x86/x64 because any RIP-relative instructions inside the stolen bytes use 32-bit signed offsets and must remain close to their original target addresses.
6. **Build Trampoline**: Copies the stolen bytes into the allocated trampoline memory and appends an absolute jump back to the remainder of the target function (`mov r10, <jmp_back_addr>; jmp r10`). The `iced-x86` library is used to re-encode and adjust RIP-relative displacement offsets.
7. **Install Hook**: Changes target memory permissions to write, overwrites the prologue of the target function with the padded relay function, restores permissions, and flushes the instruction cache.

All hooking logic is implemented in [exe/src/instructions.rs](exe/src/instructions.rs) and showcased in [exe/src/main.rs](exe/src/main.rs).

## Build

```bash
cargo build
```

## Run

```bash
cargo run
```
