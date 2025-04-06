use libc::{ftok, msgget, msgrcv, IPC_CREAT, IPC_NOWAIT};
use std::{error::Error, mem, ptr};

// Define a structure that mirrors the C++ message structure
// Make sure the layout and types match exactly!
#[repr(C)]
struct MangoAppMsgV1 {
    hdr: MsgHeader,
    visible_frametime_ns: u64,
    fsrUpscale: i32,   // Assuming g_bFSRActive is a boolean that translates to int
    fsrSharpness: f32, // Assuming g_upscaleFilterSharpness is a float
    app_frametime_ns: u64,
    latency_ns: u64,
    pid: i32,          // Assuming focusWindow_pid is an int
    outputWidth: i32,  // Assuming g_nOutputWidth is an int
    outputHeight: i32, // Assuming g_nOutputHeight is an int
    displayRefresh: u16,
    bAppWantsHDR: i32, // Assuming g_bAppWantsHDRCached is a boolean that translates to int
    bSteamFocused: i32, // Assuming g_focusedBaseAppId == 769 translates to int
    engineName: [u8; 64], // Assuming the engineName buffer is 64 bytes
                       // Add any other fields present in the C++ structure
}

#[repr(C)]
struct MsgHeader {
    msg_type: i64, // Corresponds to long in C++
    version: i32,
}

fn read_mangoapp_data() -> Result<MangoAppMsgV1, Box<dyn Error>> {
    // Generate the same key used in the C++ application
    let key = unsafe { ftok("mangoapp".as_ptr() as *const libc::c_char, 65) };
    if key == -1 {
        return Err(format!("ftok failed: {}", std::io::Error::last_os_error()).into());
    }

    // Get the message queue ID
    let msgid = unsafe { msgget(key, 0) }; // Don't use IPC_CREAT if you only want to read
    if msgid == -1 {
        return Err(format!("msgget failed: {}", std::io::Error::last_os_error()).into());
    }

    let mut msg: MangoAppMsgV1 = unsafe { mem::zeroed() };

    // Receive the message
    let result = unsafe {
        msgrcv(
            msgid,
            &mut msg as *mut _ as *mut libc::c_void,
            mem::size_of::<MangoAppMsgV1>() - mem::size_of::<i64>(), // Exclude msg_type
            1,          // Receive messages of type 1 (as set in C++)
            IPC_NOWAIT, // Non-blocking receive
        )
    };

    if result == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOMSG) {
            // No message of the requested type was found
            return Err("No message received".into());
        } else {
            return Err(format!("msgrcv failed: {}", err).into());
        }
    }

    Ok(msg)
}

fn main() -> Result<(), Box<dyn Error>> {
    match read_mangoapp_data() {
        Ok(data) => {
            println!("Received MangoApp data:");
            println!("  Visible Frametime: {}", data.visible_frametime_ns);
            println!("  FSR Upscale: {}", data.fsrUpscale);
            println!("  FSR Sharpness: {}", data.fsrSharpness);
            println!("  App Frametime: {}", data.app_frametime_ns);
            println!("  Latency: {}", data.latency_ns);
            println!("  PID: {}", data.pid);
            println!("  Output Width: {}", data.outputWidth);
            println!("  Output Height: {}", data.outputHeight);
            println!("  Display Refresh: {}", data.displayRefresh);
            println!("  App Wants HDR: {}", data.bAppWantsHDR);
            println!("  Steam Focused: {}", data.bSteamFocused);
            println!(
                "  Engine Name: {}",
                String::from_utf8_lossy(&data.engineName)
            );
        }
        Err(e) => {
            eprintln!("Error reading MangoApp data: {}", e);
        }
    }

    Ok(())
}
