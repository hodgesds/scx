// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use scx_utils::mangoapp::{mangoapp_msg_header, mangoapp_msg_v1};

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

fn main() -> Result<()> {
    unsafe {
        let key = ftok(CString::new("mangoapp").unwrap().as_ptr(), 64);
        if key == -1 {
            bail!("failed to ftok: {}", io::Error::last_os_error());
        }

        let msgid = msgget(key, 0o666 | IPC_CREAT);
        if msgid == -1 {
            bail!("failed to msgget: {}", io::Error::last_os_error());
        }

        let mut raw_msg: [u8; size_of::<mangoapp_msg_v1>()] = [0; size_of::<mangoapp_msg_v1>()];

        loop {
            let msg_size = msgrcv(
                msgid,
                raw_msg.as_mut_ptr() as *mut c_void,
                size_of::<mangoapp_msg_v1>(),
                1,
                0,
            );

            if msg_size as isize != -1 {
                let header_ptr = raw_msg.as_ptr() as *const mangoapp_msg_header;
                let header = *header_ptr; // Copy the entire header struct
                let version = header.version; // Copy the version field
                if version == 1 {
                    println!("msg: {:?}", raw_msg);
                    // if msg_size as usize > offset_of!(mangoapp_msg_v1, pid) {
                    //     HUDElements_global.g_gamescopePid =
                    //         (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).pid;
                    // }

                    // if msg_size as usize > offset_of!(mangoapp_msg_v1, visible_frametime_ns) {
                    //     let mut should_new_frame = false;
                    //     if (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).visible_frametime_ns
                    //         != u64::MAX
                    //         && (!HUDElements_global.params.no_display || logger_global.is_active())
                    //     {
                    //         update_hud_info_with_frametime(
                    //             &mut sw_stats_global,
                    //             &HUDElements_global.params,
                    //             vendorID_global,
                    //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1))
                    //                 .visible_frametime_ns,
                    //         );
                    //         should_new_frame = true;
                    //     }

                    //     if msg_size as usize > offset_of!(mangoapp_msg_v1, fsrUpscale) {
                    //         HUDElements_global.g_fsrUpscale =
                    //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).fsrUpscale;
                    //         if HUDElements_global.params.fsr_steam_sharpness < 0 {
                    //             HUDElements_global.g_fsrSharpness =
                    //                 (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).fsrSharpness
                    //                     as i32;
                    //         } else {
                    //             HUDElements_global.g_fsrSharpness = HUDElements_global
                    //                 .params
                    //                 .fsr_steam_sharpness
                    //                 - (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).fsrSharpness
                    //                     as i32;
                    //         }
                    //     }
                    //     let mut steam_focused = false;
                    //     if !HUDElements_global.params.enabled[OVERLAY_PARAM_ENABLED_mangoapp_steam]
                    //     {
                    //         steam_focused = get_prop("GAMESCOPE_FOCUSED_APP_GFX") == 769;
                    //     }

                    //     if msg_size as usize > offset_of!(mangoapp_msg_v1, latency_ns) {
                    //         gamescope_frametime(
                    //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).app_frametime_ns,
                    //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).latency_ns,
                    //         );
                    //     }

                    //     if should_new_frame {
                    //         {
                    //             let mut lk = mangoapp_m_global.lock().unwrap();
                    //             new_frame_global = true;
                    //         }
                    //         mangoapp_cv_global.notify_one();
                    //         screenWidth_global =
                    //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).outputWidth;
                    //         screenHeight_global =
                    //             (*(raw_msg.as_ptr() as *const mangoapp_msg_v1)).outputHeight;
                    //     }
                    // }
                } else {
                    bail!("Unsupported mangoapp struct version: {}", version);
                }
            } else {
                bail!(
                    "mangoapp: msgrcv returned -1 with error {}",
                    io::Error::last_os_error()
                );
            }
        }
    }

    Ok(())
}
