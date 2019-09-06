pub(crate) struct PoStSectorInfo {
    pub sector_id: u64,
    pub comm_r: [u8; 32],
    pub is_healthy: bool,
}

pub(crate) struct ProvingSet(Vec<PoStSectorInfo>);

impl ProvingSet {
    pub(crate) fn new(mut ps: Vec<PoStSectorInfo>) -> ProvingSet {
        ps.sort_by(|a, b| a.sector_id.partial_cmp(&b.sector_id).unwrap());
        ProvingSet(ps)
    }

    pub(crate) fn faulty_sector_ids(&self) -> Vec<u64> {
        self.0
            .iter()
            .filter(|PoStSectorInfo { is_healthy, .. }| *is_healthy == false)
            .map(|PoStSectorInfo { sector_id, .. }| *sector_id)
            .collect()
    }

    pub(crate) fn flattened_comm_rs(&self) -> Vec<u8> {
        self.0.iter().fold(vec![], |mut acc, item| {
            acc.append(&mut item.comm_r.to_vec());
            acc
        })
    }

    pub(crate) fn all_sector_ids(&self) -> Vec<u64> {
        self.0
            .iter()
            .map(|PoStSectorInfo { sector_id, .. }| *sector_id)
            .collect()
    }
}
