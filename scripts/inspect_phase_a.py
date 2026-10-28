#!/usr/bin/env python3
import os
import sys
import glob
import hashlib
import json
import zipfile

# Set up paths
artifacts_dir = '/home/kali/d5bundle/scripts/live_acceptance_manifest_linux_artifacts'
archive_path = '/home/kali/d5bundle/archive/proofs/68c06b8e-c7b8-4402-b98e-f6c1f2236cd9.zip'
failed_manifest = '/mnt/e/Main Project/scratch/stage-d/20261025_failed_run_256_evidence/live_acceptance_manifest_linux.json'

print('=== 1. ARCHIVE HASH & SIZE ===')
with open(archive_path, 'rb') as f:
    arc_bytes = f.read()
arc_hash = hashlib.sha256(arc_bytes).hexdigest()
print(f'Archive Path: {archive_path}')
print(f'Archive Size: {len(arc_bytes)} bytes')
print(f'Archive SHA-256: {arc_hash}')

# Compare with failed-run manifest
with open(failed_manifest, 'r') as f:
    fm_data = json.load(f)
print(f"Recorded Manifest Total Segments: {fm_data.get('total_segments_verified')}")
print(f"Recorded Manifest Total Chunks: {fm_data.get('total_chunks_processed')}")
print(f"Recorded Manifest Min Host RAM GiB: {fm_data.get('min_host_avail_gib')}")

print('\n=== 2. ARTIFACT INVENTORY ===')
proof_files = sorted(glob.glob(os.path.join(artifacts_dir, 'chunk_*_segment_*.proof')))
meta_files = sorted(glob.glob(os.path.join(artifacts_dir, 'chunk_*_segment_*.meta.json')))
pi_files = sorted(glob.glob(os.path.join(artifacts_dir, 'chunk_*_segment_*.public_inputs.json')))
body_files = sorted(glob.glob(os.path.join(artifacts_dir, 'chunk_*_segment_*.body.bin')))

print(f'Total .proof files: {len(proof_files)}')
print(f'Total .meta.json files: {len(meta_files)}')
print(f'Total .public_inputs.json files: {len(pi_files)}')
print(f'Total .body.bin files: {len(body_files)}')

print('\n=== 3. TOPOLOGY & ORDERING VALIDATION ===')
expected_keys = [f'chunk_{c}_segment_{s}' for c in range(32) for s in range(8)]

def parse_key(p):
    base = os.path.basename(p).replace('.proof', '')
    parts = base.split('_')
    return (int(parts[1]), int(parts[3]))

proof_files = sorted(proof_files, key=parse_key)
meta_files = sorted(meta_files, key=lambda p: parse_key(p.replace('.meta.json', '.proof')))
pi_files = sorted(pi_files, key=lambda p: parse_key(p.replace('.public_inputs.json', '.proof')))
body_files = sorted(body_files, key=lambda p: parse_key(p.replace('.body.bin', '.proof')))

actual_keys = [os.path.basename(p).replace('.proof', '') for p in proof_files]
assert actual_keys == expected_keys, f'Mismatch in segment ordering! diff: {len(set(actual_keys) ^ set(expected_keys))}'
print('Topology check: Exactly 32 chunks x 8 segments (0..7) in strict sequence: PASS')

print('\n=== 4. ARCHIVE ZIP MEMBER VALIDATION ===')
zf = zipfile.ZipFile(archive_path, 'r')
zip_names = set(zf.namelist())
print(f'Total members in ZIP: {len(zip_names)}')
expected_members = {f'{k}.proof' for k in expected_keys} | {'manifest.json', 'profile.json', 'segment_init_32.vk', 'segment_mid_32.vk', 'segment_final_32.vk'}
assert zip_names == expected_members, f'Archive member discrepancy! diff={zip_names ^ expected_members}'
print('ZIP member list check: Exactly 256 proof files + manifest + profile + 3 VKs: PASS')

print('\n=== 5. BIT-FOR-BIT DISK VS ZIP PROOF COMPARISON ===')
mismatches = []
proof_hashes = {}
for p in proof_files:
    fname = os.path.basename(p)
    with open(p, 'rb') as f:
        disk_p_bytes = f.read()
    zip_p_bytes = zf.read(fname)
    if disk_p_bytes != zip_p_bytes:
        mismatches.append(fname)
    proof_hashes[fname] = hashlib.sha256(disk_p_bytes).hexdigest()

assert len(mismatches) == 0, f'Mismatches found between disk and zip proofs: {mismatches}'
print('Bit-for-bit equivalence between disk artifacts and zip members: 256/256 MATCH')

print('\n=== 6. ARCHIVE MANIFEST INTEGRITY & COMMITMENTS ===')
arc_manifest = json.loads(zf.read('manifest.json'))
print(f"Job ID: {arc_manifest.get('job_id')}")
print(f"SBOM Root: {arc_manifest.get('sbom_root')}")
print(f"Vuln DB Root: {arc_manifest.get('vulnerability_db_root')}")
print(f"Policy Hash: {arc_manifest.get('policy_hash')}")
print(f"Archive Status: {arc_manifest.get('archive_status')}")
print(f"Creation Timestamp: {arc_manifest.get('creation_timestamp')}")

# Check manifest segment hashes against computed proof hashes
manifest_segments = arc_manifest.get('segments', [])
assert len(manifest_segments) == 256, f"Expected 256 segments in manifest, got {len(manifest_segments)}"
for seg_entry in manifest_segments:
    fn = seg_entry['filename']
    assert proof_hashes[fn] == seg_entry['proof_hash'], f"Proof hash mismatch for {fn} in archive manifest!"
print('Archive manifest segment hashes match computed proof hashes: 256/256 PASS')

print('\n=== 7. PROFILE-LEVEL ARCHIVE VALIDATION ===')
os.environ['CRYPTO_PROFILE'] = 'prod'
sys.path.insert(0, '/home/kali/d5bundle')
sys.path.insert(0, '/home/kali/d5bundle/backend')
from shared.crypto.config import get_crypto_profile
p = get_crypto_profile()
p.validate_proof_archive(
    archive_path,
    expected_hash=arc_hash,
    expected_proof_count=256,
    expected_member_hashes=proof_hashes,
    expected_manifest={
        'job_id': arc_manifest['job_id'],
        'sbom_upload_id': arc_manifest['sbom_upload_id'],
        'snapshot_id': arc_manifest['snapshot_id'],
        'sbom_root': arc_manifest['sbom_root'],
        'vulnerability_db_root': arc_manifest['vulnerability_db_root'],
        'policy_hash': arc_manifest['policy_hash'],
        'total_chunks': 32,
        'total_segments': 256,
    }
)
print('profile.validate_proof_archive (with full expected_manifest & member hashes): PASS')
print('\n=== PHASE A READ-ONLY AUDIT COMPLETE: ALL CHECKS PASSED ===')
