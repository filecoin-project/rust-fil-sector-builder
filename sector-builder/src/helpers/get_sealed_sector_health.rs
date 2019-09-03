use crate::helpers::compute_checksum::compute_checksum;
use crate::{SealedSectorHealth, SealedSectorMetadata};
use std::path::Path;

pub fn get_sealed_sector_health<T: AsRef<Path>>(
    sealed_sector_path: T,
    meta: &SealedSectorMetadata,
) -> Result<SealedSectorHealth, failure::Error> {
    // compare lengths
    if std::fs::metadata(&sealed_sector_path)?.len() != meta.len {
        return Ok(SealedSectorHealth::ErrorInvalidLength);
    }

    // compare checksums
    if compute_checksum(&sealed_sector_path)?.as_bytes() != meta.blake2b_checksum.as_slice() {
        return Ok(SealedSectorHealth::ErrorInvalidChecksum);
    }

    Ok(SealedSectorHealth::Ok)
}