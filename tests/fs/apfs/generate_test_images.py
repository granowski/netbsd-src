#!/usr/bin/env python3
"""
Test image generator for APFS Space Manager validation.
Generates real APFS images using macOS native tools or synthetic fixtures.
"""

import os
import sys
import subprocess
import tempfile
import struct

sys.path.insert(0, os.path.dirname(__file__))
from ref_spaceman import fletcher64

def run_cmd(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nStderr: {res.stderr}")
    return res.stdout

def create_fresh_image(path: str, size_mb: int = 50, volname: str = "FreshAPFS"):
    """Creates a fresh, formatted APFS container."""
    if os.path.exists(path):
        os.remove(path)
    run_cmd(f"hdiutil create -size {size_mb}m -fs APFS -volname '{volname}' -layout NONE '{path}'")

def create_populated_image(path: str, size_mb: int = 100, volname: str = "PopulatedAPFS"):
    """Creates an APFS container with populated files."""
    if os.path.exists(path):
        os.remove(path)
    run_cmd(f"hdiutil create -size {size_mb}m -fs APFS -volname '{volname}' -layout NONE '{path}'")
    
    # Attach image (macOS auto-mounts at /Volumes/<volname>)
    out = run_cmd(f"hdiutil attach '{path}'")
    dev = None
    mount_dir = None
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 1 and "/dev/disk" in parts[0]:
            if not dev:
                dev = parts[0].strip()
        if len(parts) >= 3 and os.path.exists(parts[2].strip()):
            mount_dir = parts[2].strip()

    if not dev or not mount_dir:
        raise RuntimeError(f"Could not determine device/mount for attached image: {out}")

    try:
        # Write files of various sizes
        with open(os.path.join(mount_dir, "small.txt"), "w") as f:
            f.write("Hello APFS Space Manager\n" * 100)

        with open(os.path.join(mount_dir, "medium.bin"), "wb") as f:
            f.write(os.urandom(1024 * 1024 * 5)) # 5MB

        with open(os.path.join(mount_dir, "large.bin"), "wb") as f:
            f.write(b"\xaa" * (1024 * 1024 * 15)) # 15MB

        # Create subdirectories and files
        os.makedirs(os.path.join(mount_dir, "subdir"), exist_ok=True)
        with open(os.path.join(mount_dir, "subdir", "subfile.bin"), "wb") as f:
            f.write(b"\x55" * (1024 * 512)) # 512KB

        # Unlink one file to exercise deleted blocks / fragmentation
        with open(os.path.join(mount_dir, "temp_to_delete.bin"), "wb") as f:
            f.write(b"\xff" * (1024 * 1024 * 2))
        os.remove(os.path.join(mount_dir, "temp_to_delete.bin"))
        run_cmd("sync")
    finally:
        run_cmd(f"hdiutil detach {dev} || diskutil eject {dev}")

def create_multi_chunk_image(path: str, size_mb: int = 300, volname: str = "MultiChunkAPFS"):
    """Creates a larger APFS container (300MB = 76,800 blocks > 32,768 blocks/chunk = at least 3 chunks)."""
    if os.path.exists(path):
        os.remove(path)
    run_cmd(f"hdiutil create -size {size_mb}m -fs APFS -volname '{volname}' -layout NONE '{path}'")

def main():
    out_dir = "/tmp/apfs_test_images"
    os.makedirs(out_dir, exist_ok=True)
    
    fresh_path = os.path.join(out_dir, "fresh_50m.dmg")
    print(f"Creating fresh image at {fresh_path}...")
    create_fresh_image(fresh_path, 50)
    
    pop_path = os.path.join(out_dir, "populated_100m.dmg")
    print(f"Creating populated image at {pop_path}...")
    create_populated_image(pop_path, 100)

    multi_path = os.path.join(out_dir, "multichunk_300m.dmg")
    print(f"Creating multi-chunk image at {multi_path}...")
    create_multi_chunk_image(multi_path, 300)

    print("All test images created successfully in", out_dir)

if __name__ == "__main__":
    main()
