use anyhow::{bail, Result};

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// https://github.com/amd/amd_energy
/// See msr-index.h for a list of MSRs

/// Unit Multipliers used in RAPL Interfaces (R/O)  See Section 14.7.1, RAPL Interfaces.
// pub const MSR_RAPL_POWER_UNIT: u64 = 0x00000606;
// pub const MSR_RAPL_POWER_UNIT: u64 = 0x000a1003; //0x606;
pub const MSR_RAPL_POWER_UNIT: u64 = 0x606;

pub const MSR_AMD_RAPL_POWER_UNIT: u64 = 0xc0010299;

pub const AMD_ENERGY_UNIT_MASK: u64 = 0x01F00;

/// PKG Energy Status (R/O)  See Section 14.7.3, Package RAPL Domain.
pub const MSR_PKG_ENERGY_STATUS: u32 = 0x611;

/// Package RAPL Perf Status (R/O)
pub const MSR_PKG_PERF_STATUS: u32 = 0x613;

/// PKG RAPL Parameters (R/W) See Section 14.7.3,  Package RAPL  Domain.
pub const MSR_PKG_POWER_INFO: u32 = 0x614;

pub fn read_msr(cpu: i32, offset: u64) -> Result<u64> {
    let pathname = format!("/dev/cpu/{}/msr", cpu);
    let mut file = File::open(Path::new(&pathname))?;

    file.seek(SeekFrom::Start(offset))?;

    let mut buf = [0u8; 8];
    let bytes_read = file.read_exact(&mut buf)?;

    Ok(u64::from_le_bytes(buf))
}

pub enum PowerUnit {
    Joules,
    Watts,
}

impl PowerUnit {
    /// Returns the default power unit for the hardware.
    pub fn default() -> Result<PowerUnit> {
        let power_unit = read_msr(0, MSR_AMD_RAPL_POWER_UNIT)?;
        match power_unit {
            _ => {
                // bail!("Unknown power unit: {}", power_unit);
                Ok(PowerUnit::Watts)
            }
        }
    }
}
