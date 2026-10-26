import sys

filepath = 'backend/vulnerability_service/app/api/routes/vulnerability_routes.py'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

new_route = '''
@router.post('/snapshots/{snapshot_id}/freeze', response_model=VulnerabilitySnapshotResponse)
def freeze_snapshot(snapshot_id: UUID, db: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    from shared.crypto.smt import SparseMerkleTree
    from shared.crypto.poseidon_bn254 import poseidon_hash
    from datetime import datetime, timezone
    
    if current_user.role != 'admin':
        raise HTTPException(status_code=403, detail='Admin role required for freezing')
    
    snap = db.query(VulnerabilitySnapshot).filter(VulnerabilitySnapshot.id == snapshot_id).first()
    if not snap:
        raise HTTPException(status_code=404, detail='Snapshot not found')
        
    if snap.status != 'approved':
        raise HTTPException(status_code=400, detail='Snapshot can only be frozen from approved state')
        
    # Recompute the authoritative SMT root
    smt = SparseMerkleTree()
    for mapping in snap.mappings:
        comp_hash_int = int(mapping.component_hash, 16)
        leaf_hash = poseidon_hash([comp_hash_int, mapping.max_cvss])
        smt.insert(comp_hash_int, leaf_hash)
        
    authoritative_root = smt.get_root()
    snap.authoritative_smt_root = f"0x{authoritative_root:064x}"
    snap.frozen_at = datetime.now(timezone.utc)
    snap.status = 'frozen'
    
    db.commit()
    return VulnerabilitySnapshotResponse.from_model(snap)
'''

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content + new_route)
