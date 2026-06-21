use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The function to hook and test
    #[arg(short, long, value_enum, default_value_t = HookTarget::MessageBoxA)]
    pub target: HookTarget,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum HookTarget {
    MessageBoxA,
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
