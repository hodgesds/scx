use anyhow::bail;
use anyhow::Result;
use libc::{ftok, msgget, msgrcv, IPC_CREAT};

use std::mem::size_of;
use std::os::raw::c_void;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use std::{ffi::CString, io, mem::offset_of};

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct mangoapp_msg_header {
    pub msg_type: libc::c_long,
    pub version: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct mangoapp_msg_v1 {
    pub hdr: mangoapp_msg_header,
    pub pid: u32,
    pub visible_frametime_ns: u64,
    pub fsrUpscale: u8,
    pub fsrSharpness: u8,
    pub app_frametime_ns: u64,
    pub latency_ns: u64,
    pub outputWidth: u32,
    pub outputHeight: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct mangoapp_ctrl_header {
    pub msg_type: libc::c_long,
    pub ctrl_msg_type: u32,
    pub version: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct mangoapp_ctrl_msgid1_v1 {
    pub hdr: mangoapp_ctrl_header,
    pub no_display: u8,
    pub log_session: u8,
    pub log_session_name: [libc::c_char; 64],
    pub reload_config: u8,
}

// Assuming you have these external functions and variables defined elsewhere.
// Replace with the actual implementations or stubs.
// extern crate some_external_crate;
// use some_external_crate::{HUDElements, params, logger, update_hud_info_with_frametime, gamescope_frametime, get_prop, EngineTypes, sw_stats, vendorID};
// use some_external_crate::{new_frame, mangoapp_m, mangoapp_cv, screenWidth, screenHeight, OVERLAY_PARAM_ENABLED_mangoapp_steam};

// Example stubs for external dependencies

// struct Params {
//     no_display: bool,
//     fsr_steam_sharpness: i32,
//     enabled: [bool; 10], // Example size
// }
//
// struct HUDElements {
//     g_gamescopePid: u32,
//     g_fsrUpscale: u8,
//     g_fsrSharpness: i32,
//     params: Arc<Params>,
// }
//
// struct Logger {
//     active: bool,
// }
//
// impl Logger {
//     fn is_active(&self) -> bool {
//         self.active
//     }
// }
//
// fn update_hud_info_with_frametime(
//     _sw_stats: &mut i32,
//     _params: &Params,
//     _vendor_id: i32,
//     _frametime: u64,
// ) {
//     // Implement or stub
// }
//
// fn gamescope_frametime(_app_frametime: u64, _latency: u64) {
//     // Implement or stub
// }
//
// fn get_prop(_prop_name: &str) -> i32 {
//     // Implement or stub
//     0
// }
//
// enum EngineTypes {
//     GAMESCOPE,
// }
//
// // Example global variables (replace with proper state management)
// static mut HUDElements_global: HUDElements = HUDElements {
//     g_gamescopePid: 0,
//     g_fsrUpscale: 0,
//     g_fsrSharpness: 0,
//     params: Arc::new(Params {
//         no_display: false,
//         fsr_steam_sharpness: 0,
//         enabled: [false; 10],
//     }),
// };
//
// static mut logger_global: Logger = Logger { active: false };
// static mut sw_stats_global: i32 = 0;
// static vendorID_global: i32 = 0;
// static new_frame_global: bool = false;
// static mangoapp_m_global: Mutex<bool> = Mutex::new(false);
// static mangoapp_cv_global: Condvar = Condvar::new();
// static mut screenWidth_global: u32 = 0;
// static mut screenHeight_global: u32 = 0;
// const OVERLAY_PARAM_ENABLED_mangoapp_steam: usize = 0;
//
// pub fn process_mangoapp_messages() -> Result<()> {
//     unsafe {
//         let key = ftok(CString::new("mangoapp").unwrap().as_ptr(), 65);
//         if key == -1 {
//             bail!("failed to ftok: {}", io::Error::last_os_error());
//         }
//
//         let msgid = msgget(key, 0o666 | IPC_CREAT);
//         if msgid == -1 {
//             bail!("failed to msgget: {}", io::Error::last_os_error());
//         }
//
//         let mut raw_msg: [u8; size_of::<mangoapp_msg_v1>()] = [0; size_of::<mangoapp_msg_v1>()];
//
//         loop {
//             let msg_size = msgrcv(
//                 msgid,
//                 raw_msg.as_mut_ptr() as *mut c_void,
//                 size_of::<mangoapp_msg_v1>(),
//                 1,
//                 0,
//             );
//
//             if msg_size as isize != -1 {
//                 if (*(raw_msg.as_ptr() as *const mangoapp_msg_header)).version == 1 {
//                     println!("msg: {}", raw_msg);
//                     // if msg_size as usize > offset_of!(mangoapp_msg_v1, pid) {
//                     //     HUDElements_global.g_gamescopePid =
//                     //         (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).pid;
//                     // }
//
//                     // if msg_size as usize > offset_of!(mangoapp_msg_v1, visible_frametime_ns) {
//                     //     let mut should_new_frame = false;
//                     //     if (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).visible_frametime_ns
//                     //         != u64::MAX
//                     //         && (!HUDElements_global.params.no_display || logger_global.is_active())
//                     //     {
//                     //         update_hud_info_with_frametime(
//                     //             &mut sw_stats_global,
//                     //             &HUDElements_global.params,
//                     //             vendorID_global,
//                     //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1))
//                     //                 .visible_frametime_ns,
//                     //         );
//                     //         should_new_frame = true;
//                     //     }
//
//                     //     if msg_size as usize > offset_of!(mangoapp_msg_v1, fsrUpscale) {
//                     //         HUDElements_global.g_fsrUpscale =
//                     //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).fsrUpscale;
//                     //         if HUDElements_global.params.fsr_steam_sharpness < 0 {
//                     //             HUDElements_global.g_fsrSharpness =
//                     //                 (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).fsrSharpness
//                     //                     as i32;
//                     //         } else {
//                     //             HUDElements_global.g_fsrSharpness = HUDElements_global
//                     //                 .params
//                     //                 .fsr_steam_sharpness
//                     //                 - (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).fsrSharpness
//                     //                     as i32;
//                     //         }
//                     //     }
//                     //     let mut steam_focused = false;
//                     //     if !HUDElements_global.params.enabled[OVERLAY_PARAM_ENABLED_mangoapp_steam]
//                     //     {
//                     //         steam_focused = get_prop("GAMESCOPE_FOCUSED_APP_GFX") == 769;
//                     //     }
//
//                     //     if msg_size as usize > offset_of!(mangoapp_msg_v1, latency_ns) {
//                     //         gamescope_frametime(
//                     //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).app_frametime_ns,
//                     //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).latency_ns,
//                     //         );
//                     //     }
//
//                     //     if should_new_frame {
//                     //         {
//                     //             let mut lk = mangoapp_m_global.lock().unwrap();
//                     //             new_frame_global = true;
//                     //         }
//                     //         mangoapp_cv_global.notify_one();
//                     //         screenWidth_global =
//                     //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).outputWidth;
//                     //         screenHeight_global =
//                     //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).outputHeight;
//                     //     }
//                     // }
//                 } else {
//                     bail!(
//                         "Unsupported mangoapp struct version: {}",
//                         (*(raw_msg.as_ptr() as *const mangoapp_msg_header)).version
//                     );
//                 }
//             } else {
//                 bail!(
//                     "mangoapp: msgrcv returned -1 with error {} - {}",
//                     libc::errno(),
//                     io::Error::last_os_error()
//                 );
//             }
//         }
//     }
//     Ok(())
// }
