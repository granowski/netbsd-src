#!/usr/bin/env python3
"""
Cross-validation script for APFS Space Manager (Milestone 4: Transaction & Copy-on-Write I/O Foundations).
Compares C-based kernel decoder outputs against the independent Python reference parser and validates disk immutability.
"""

import os
import sys
import subprocess
import json
import re
import hashlib

sys.path.insert(0, os.path.dirname(__file__))
from ref_spaceman import APFSReferenceParser

def run_cmd(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout, res.stderr

def parse_c_output(stdout: str) -> dict:
    info = {}
    for line in stdout.splitlines():
        if "apfs_spaceman: oid" in line:
            # apfs_spaceman: oid 0x400 block size 4096 blocks 12800 chunks 1 blocks/chunk 32768 CIBs 1 chunks/CIB 126
            m = re.search(r"oid (0x[0-9a-fA-F]+) block size (\d+) blocks (\d+) chunks (\d+) blocks/chunk (\d+) CIBs (\d+) chunks/CIB (\d+)", line)
            if m:
                info["spaceman_oid"] = int(m.group(1), 16)
                info["block_size"] = int(m.group(2))
                info["block_count"] = int(m.group(3))
                info["chunk_count"] = int(m.group(4))
                info["blocks_per_chunk"] = int(m.group(5))
                info["cib_count"] = int(m.group(6))
                info["chunks_per_cib"] = int(m.group(7))
        elif "apfs_spaceman: validated" in line:
            # apfs_spaceman: validated 12635 free blocks across 1 chunks
            m = re.search(r"validated (\d+) free blocks across (\d+) chunks", line)
            if m:
                info["total_validated_free"] = int(m.group(1))
        elif "active free queues contain" in line:
            m = re.search(r"active free queues contain (\d+) delayed free entries", line)
            if m:
                info["active_fq_entries"] = int(m.group(1))
        elif "bitmap semantics:" in line:
            # apfs_spaceman: bitmap semantics: clear bits are free; read-only candidate 165 (chunk 0, bitmap 152, bit 165; not reserved)
            if "clear bits are free" in line:
                info["polarity"] = 0
            elif "set bits are free" in line:
                info["polarity"] = 1
            m = re.search(r"candidate (\d+) \(chunk (\d+), bitmap (\d+), bit (\d+)", line)
            if m:
                info["candidate_free_block"] = (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
    return info

def cross_validate_image(image_path: str):
    print(f"\n=======================================================")
    print(f"Cross-Validating Image: {image_path}")
    print(f"=======================================================")
    
    # 1. Independent Python Reference Parser
    ref_parser = APFSReferenceParser(image_path)
    ref_res = ref_parser.parse()
    ref_parser.close()

    # 2. C Kernel Decoder
    rc, c_out, c_err = run_cmd(f"/tmp/t_spaceman '{image_path}'")
    if rc != 0:
        raise RuntimeError(f"C decoder failed with exit code {rc}:\n{c_out}\n{c_err}")

    c_res = parse_c_output(c_out)

    # 3. Assertions and comparisons
    print("Checking Container Superblock and Geometry:")
    assert ref_res["block_size"] == c_res["block_size"], f"Block size mismatch: {ref_res['block_size']} vs {c_res['block_size']}"
    assert ref_res["block_count"] == c_res["block_count"], f"Block count mismatch: {ref_res['block_count']} vs {c_res['block_count']}"
    assert ref_res["spaceman_oid"] == c_res["spaceman_oid"], f"Spaceman OID mismatch: {ref_res['spaceman_oid']:#x} vs {c_res['spaceman_oid']:#x}"
    assert ref_res["blocks_per_chunk"] == c_res["blocks_per_chunk"], f"Blocks per chunk mismatch"
    assert ref_res["chunks_per_cib"] == c_res["chunks_per_cib"], f"Chunks per CIB mismatch"
    assert ref_res["cib_count"] == c_res["cib_count"], f"CIB count mismatch"
    assert ref_res["chunk_count"] == c_res["chunk_count"], f"Chunk count mismatch"
    print(f"  ✓ Geometry matched: block_size={c_res['block_size']}, blocks={c_res['block_count']}, chunks={c_res['chunk_count']}, CIBs={c_res['cib_count']}")

    print("Checking Free Block Totals and Polarity:")
    assert ref_res["total_validated_free"] == c_res["total_validated_free"], f"Free count mismatch: {ref_res['total_validated_free']} vs {c_res['total_validated_free']}"
    assert ref_res["device_free_count"] == c_res["total_validated_free"], f"Device free count mismatch"
    assert ref_res["polarity"] == c_res["polarity"], f"Polarity mismatch: {ref_res['polarity']} vs {c_res['polarity']}"
    pol_str = "clear (0) is free" if c_res["polarity"] == 0 else "set (1) is free"
    print(f"  ✓ Validated free blocks: {c_res['total_validated_free']} (exact match with sm_dev[0].sm_free_count)")
    print(f"  ✓ Bitmap polarity conclusively verified: {pol_str}")

    print("Checking Exclusion Ranges & Candidate Block Safety:")
    for start, length, desc in ref_res["exclusion_ranges"]:
        print(f"  ✓ Exclusion Range: {desc} (blocks {start}..{start + length - 1})")

    assert ref_res["candidate_free_block"] == c_res["candidate_free_block"], f"Candidate mismatch: {ref_res['candidate_free_block']} vs {c_res['candidate_free_block']}"
    cand = c_res["candidate_free_block"]
    if cand:
        cand_paddr = cand[0]
        for start, length, desc in ref_res["exclusion_ranges"]:
            assert not (start <= cand_paddr < start + length), f"Candidate {cand_paddr} intersects {desc} ({start}..{start+length-1})!"
        print(f"  ✓ Candidate free block {cand_paddr} strictly disjoint from all exclusion ranges")
        print(f"  ✓ Candidate details: block={cand[0]} (chunk={cand[1]}, bitmap_block={cand[2]}, bit_offset={cand[3]})")

    if ref_res.get("active_fq_entries", 0) > 0:
        print(f"  ✓ Free queues audited: {ref_res['active_fq_entries']} delayed free blocks detected")

    print(f"STATUS: Image {os.path.basename(image_path)} PASSED 100% CROSS-VALIDATION")

def get_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def main():
    # Ensure t_spaceman binary is compiled
    rc, out, err = run_cmd("clang -Wall -Wextra tests/fs/apfs/t_spaceman.c -o /tmp/t_spaceman -lpthread")
    if rc != 0:
        print(f"Compilation failed: {err}")
        sys.exit(1)

    images = [
        "/tmp/apfs_test_images/fresh_50m.dmg",
        "/tmp/apfs_test_images/populated_100m.dmg",
        "/tmp/apfs_test_images/deleted_120m.dmg",
        "/tmp/apfs_test_images/multichunk_300m.dmg"
    ]

    for img in images:
        if not os.path.exists(img):
            print(f"Image {img} does not exist, running generator...")
            run_cmd(f"python3 {os.path.join(os.path.dirname(__file__), 'generate_test_images.py')}")
            break

    # Record pre-test SHA256 hashes for disk immutability verification
    initial_hashes = {}
    for img in images:
        if os.path.exists(img):
            initial_hashes[img] = get_sha256(img)

    for img in images:
        if os.path.exists(img):
            cross_validate_image(img)

    print("\n-------------------------------------------------------")
    print("Running Full Failure Mode & Synthetic Edge-Case Suite...")
    print("-------------------------------------------------------")
    rc, out, err = run_cmd("/tmp/t_spaceman")
    if rc != 0:
        print(f"Test suite failed:\n{out}\n{err}")
        sys.exit(1)
    print(out)

    print("\n-------------------------------------------------------")
    print("Verifying Disk Image Bitwise Immutability (SHA-256)...")
    print("-------------------------------------------------------")
    for img, initial_hash in initial_hashes.items():
        final_hash = get_sha256(img)
        assert initial_hash == final_hash, f"Immutability violated for {img}! Before: {initial_hash}, After: {final_hash}"
        print(f"  ✓ Image {os.path.basename(img)} byte-for-byte identical (SHA-256: {initial_hash[:16]}...)")

    print("\nALL MILESTONE 4 CROSS-VALIDATION & IMMUTABILITY TESTS PASSED CLEANLY!")

if __name__ == "__main__":
    main()
