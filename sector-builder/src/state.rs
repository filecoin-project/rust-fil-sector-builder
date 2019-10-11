use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use storage_proofs::sector::SectorId;

use crate::metadata::{SealedSectorMetadata, StagedSectorMetadata};
use crate::SealTicket;

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct StagedState {
    pub sectors: HashMap<SectorId, StagedSectorMetadata>,
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct SealedState {
    pub sectors: HashMap<SectorId, SealedSectorMetadata>,
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct SectorBuilderState {
    pub current_seal_ticket: SealTicket,
    pub last_committed_sector_id: SectorId,
    pub staged: StagedState,
    pub sealed: SealedState,
}

impl SectorBuilderState {
    pub fn new(
        current_seal_ticket: SealTicket,
        last_committed_sector_id: SectorId,
    ) -> SectorBuilderState {
        SectorBuilderState {
            current_seal_ticket,
            last_committed_sector_id,
            staged: StagedState {
                sectors: Default::default(),
            },
            sealed: Default::default(),
        }
    }
}
