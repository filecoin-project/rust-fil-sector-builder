use filecoin_proofs::types::UnpaddedBytesAmount;
use filecoin_proofs::PersistentAux;
use serde::{Deserialize, Serialize};
use storage_proofs::sector::SectorId;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct StagedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
    pub seal_status: SealStatus,
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Debug)]
pub struct SealedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
    pub comm_r: [u8; 32],
    pub comm_d: [u8; 32],
    pub proof: Vec<u8>,
    /// checksum on the whole sector
    pub blake2b_checksum: Vec<u8>,
    /// number of bytes in the sealed sector-file as returned by `std::fs::metadata`
    pub len: u64,
    pub p_aux: PersistentAux,
    pub seal_ticket: SealTicket,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PieceMetadata {
    pub piece_key: String,
    pub num_bytes: UnpaddedBytesAmount,
    pub comm_p: Option<[u8; 32]>,
    pub piece_inclusion_proof: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SealStatus {
    Failed(String),
    Pending,
    Sealed(Box<SealedSectorMetadata>),
    ReadyForSealing,
    Sealing(SealTicket),
}

impl PartialEq for SealStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SealStatus::Failed(_), SealStatus::Failed(_)) => true,
            (SealStatus::Pending, SealStatus::Pending) => true,
            (SealStatus::Sealed(_), SealStatus::Sealed(_)) => true,
            (SealStatus::ReadyForSealing, SealStatus::ReadyForSealing) => true,
            (SealStatus::Sealing(_), SealStatus::Sealing(_)) => true,
            (_, _) => false,
        }
    }
}

#[derive(Clone, Serialize, Default, Deserialize, Debug, PartialEq)]
pub struct SealTicket {
    pub height: u64,
    pub bytes: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SealedSectorHealth {
    Ok,
    ErrorInvalidChecksum,
    ErrorInvalidLength,
    ErrorMissing,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GetSealedSectorResult {
    WithHealth(SealedSectorHealth, SealedSectorMetadata),
    WithoutHealth(SealedSectorMetadata),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct SecondsSinceEpoch(pub u64);

impl Default for StagedSectorMetadata {
    fn default() -> StagedSectorMetadata {
        StagedSectorMetadata {
            sector_id: Default::default(),
            sector_access: Default::default(),
            pieces: Default::default(),
            seal_status: SealStatus::Pending,
        }
    }
}
