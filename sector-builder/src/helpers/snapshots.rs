use std::sync::Arc;

use byteorder::{LittleEndian, WriteBytesExt};
use filecoin_proofs::types::PaddedBytesAmount;

use crate::builder::WrappedKeyValueStore;
use crate::error::Result;
use crate::kv_store::KeyValueStore;
use crate::state::*;

#[derive(Clone)]
pub struct SnapshotKey {
    prover_id: [u8; 31],
    sector_size: PaddedBytesAmount,
}

impl SnapshotKey {
    pub fn new(prover_id: [u8; 31], sector_size: PaddedBytesAmount) -> SnapshotKey {
        SnapshotKey {
            prover_id,
            sector_size,
        }
    }
}

pub fn load_snapshot<T: KeyValueStore>(
    kv_store: &Arc<WrappedKeyValueStore<T>>,
    key: SnapshotKey,
) -> Result<Option<StateSnapshot>> {
    let result: Option<Vec<u8>> = kv_store.inner().get(&Vec::from(key))?;

    if let Some(val) = result {
        return serde_cbor::from_slice(&val[..])
            .map_err(failure::Error::from)
            .map(Option::Some);
    }

    Ok(None)
}

impl From<SnapshotKey> for Vec<u8> {
    fn from(n: SnapshotKey) -> Self {
        // convert the sector size to a byte vector
        let mut snapshot_key = vec![];
        snapshot_key
            .write_u64::<LittleEndian>(u64::from(n.sector_size))
            .unwrap();

        // concatenate the prover id bytes
        snapshot_key.extend_from_slice(&n.prover_id[..]);

        snapshot_key
    }
}

pub fn persist_snapshot<T: KeyValueStore>(
    kv_store: &Arc<WrappedKeyValueStore<T>>,
    key: SnapshotKey,
    snapshot: &StateSnapshot,
) -> Result<()> {
    let serialized = serde_cbor::to_vec(snapshot)?;
    kv_store.inner().put(&Vec::from(key), &serialized)?;
    Ok(())
}

pub fn make_snapshot(staged_state: &StagedState, sealed_state: &SealedState) -> StateSnapshot {
    StateSnapshot {
        staged: StagedState {
            sector_id_nonce: staged_state.sector_id_nonce,
            sectors: staged_state.sectors.clone(),
        },
        sealed: SealedState {
            sectors: sealed_state.sectors.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::builder::{SectorId, WrappedKeyValueStore};
    use crate::kv_store::SledKvs;
    use crate::metadata::StagedSectorMetadata;
    use crate::state::StagedState;

    use super::*;

    #[test]
    fn test_snapshotting() {
        let metadata_dir = tempfile::tempdir().unwrap();

        let kv_store = Arc::new(WrappedKeyValueStore::new(
            SledKvs::initialize(metadata_dir).unwrap(),
        ));

        // create a snapshot to persist and load
        let snapshot_a = {
            let mut m: HashMap<SectorId, StagedSectorMetadata> = HashMap::new();

            m.insert(123, Default::default());

            let staged_state = StagedState {
                sector_id_nonce: 100,
                sectors: m,
            };

            let sealed_state = Default::default();

            make_snapshot(&staged_state, &sealed_state)
        };

        // create a second (different) snapshot
        let snapshot_b = {
            let mut m: HashMap<SectorId, StagedSectorMetadata> = HashMap::new();

            m.insert(666, Default::default());

            let staged_state = StagedState {
                sector_id_nonce: 102,
                sectors: m,
            };

            let sealed_state = Default::default();

            make_snapshot(&staged_state, &sealed_state)
        };

        let key_a = SnapshotKey::new([0; 31], PaddedBytesAmount(1024));
        let key_b = SnapshotKey::new([0; 31], PaddedBytesAmount(1111));
        let key_c = SnapshotKey::new([1; 31], PaddedBytesAmount(1024));

        // persist both snapshots
        let _ = persist_snapshot(&kv_store, key_a.clone(), &snapshot_a).unwrap();
        let _ = persist_snapshot(&kv_store, key_b.clone(), &snapshot_b).unwrap();

        // load both snapshots
        let loaded_a = load_snapshot(&kv_store, key_a).unwrap().unwrap();
        let loaded_b = load_snapshot(&kv_store, key_b).unwrap().unwrap();

        // key corresponds to no snapshot
        let lookup_miss = load_snapshot(&kv_store, key_c).unwrap();

        assert_eq!(snapshot_a, loaded_a);
        assert_eq!(snapshot_b, loaded_b);
        assert_eq!(true, lookup_miss.is_none());
    }
}
