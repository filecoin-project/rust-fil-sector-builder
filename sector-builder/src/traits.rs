use crate::{GetSealedSectorResult, SealStatus, SecondsSinceEpoch, StagedSectorMetadata};
use storage_proofs::sector::SectorId;

pub trait SectorBuilder {
    // Stages user piece-bytes for sealing.
    fn add_piece(
        &self,
        piece_key: String,
        piece_bytes_amount: u64,
        piece_path: String,
        store_until: SecondsSinceEpoch,
    ) -> std::result::Result<SectorId, failure::Error>;

    // Returns sealing status for the sector with specified id. If no sealed or
    // staged sector exists with the provided id, produce an error.
    fn get_seal_status(
        &self,
        sector_id: SectorId,
    ) -> std::result::Result<SealStatus, failure::Error>;

    // Unseals the sector containing the referenced piece and returns its
    // bytes. Produces an error if this sector builder does not have a sealed
    // sector containing the referenced piece.
    fn read_piece_from_sealed_sector(
        &self,
        piece_key: String,
    ) -> std::result::Result<Vec<u8>, failure::Error>;

    // For demo purposes. Schedules sealing of all staged sectors.
    fn seal_all_staged_sectors(&self) -> std::result::Result<(), failure::Error>;

    // Returns all sealed sector metadata.
    fn get_sealed_sectors(
        &self,
        check_health: bool,
    ) -> std::result::Result<Vec<GetSealedSectorResult>, failure::Error>;

    // Returns all staged sector metadata.
    fn get_staged_sectors(&self) -> std::result::Result<Vec<StagedSectorMetadata>, failure::Error>;

    // Generates a proof-of-spacetime.
    fn generate_post(
        &self,
        comm_rs: &[[u8; 32]],
        challenge_seed: &[u8; 32],
        faults: Vec<SectorId>,
    ) -> std::result::Result<Vec<u8>, failure::Error>;
}
