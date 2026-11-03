#!/usr/bin/env python3
"""
Independent APFS Space Manager reference parser and validator.
Decodes container superblock, checkpoint map, spaceman object, CIBs, and bitmaps.
"""

import sys
import os
import struct

OBJ_CONTAINER_SUPERBLOCK = 0x00000001
OBJ_SPACEMAN             = 0x00000005
OBJ_SPACEMAN_CAB         = 0x00000006
OBJ_SPACEMAN_CIB         = 0x00000007
OBJ_SPACEMAN_BITMAP      = 0x00000008
OBJ_CHECKPOINT_MAP       = 0x0000000c
OBJECT_TYPE_MASK         = 0x0000ffff

def fletcher64(buf: bytes) -> int:
    """Calculate APFS-specific complemented Fletcher-64 checksum."""
    words = struct.unpack(f"<{len(buf)//4}I", buf)
    s1, s2 = 0, 0
    # Skip first 8 bytes (checksum itself)
    for w in words[2:]:
        s1 += w
        s2 += s1
    mod = 0xffffffff
    c1 = mod - ((s1 + s2) % mod)
    c2 = mod - ((s1 + c1) % mod)
    return (c2 << 32) | c1

def verify_checksum(buf: bytes) -> bool:
    stored, = struct.unpack("<Q", buf[0:8])
    return fletcher64(buf) == stored

class APFSReferenceParser:
    def __init__(self, filename: str):
        self.filename = filename
        self.f = open(filename, "rb")
        self.file_size = os.path.getsize(filename)
        self.block_size = 4096
        self.raw_blocks = {}

    def close(self):
        self.f.close()

    def read_block(self, paddr: int) -> bytes:
        if paddr < 0 or (paddr + 1) * self.block_size > self.file_size:
            raise ValueError(f"paddr {paddr} out of bounds")
        if paddr in self.raw_blocks:
            return self.raw_blocks[paddr]
        self.f.seek(paddr * self.block_size)
        data = self.f.read(self.block_size)
        if len(data) != self.block_size:
            raise IOError(f"short read at paddr {paddr}")
        self.raw_blocks[paddr] = data
        return data

    def parse(self) -> dict:
        # 1. Container Superblock (block 0)
        sb_raw = self.read_block(0)
        if not verify_checksum(sb_raw):
            raise ValueError("Container superblock checksum mismatch")

        magic = sb_raw[32:36]
        if magic != b"NXSB":
            raise ValueError(f"Invalid container magic {magic}")

        self.block_size, = struct.unpack("<I", sb_raw[36:40])
        self.block_count, = struct.unpack("<Q", sb_raw[40:48])
        self.spaceman_oid, = struct.unpack("<Q", sb_raw[152:160])
        xp_desc_blocks, = struct.unpack("<I", sb_raw[104:108])
        xp_data_blocks, = struct.unpack("<I", sb_raw[108:112])
        xp_desc_base, = struct.unpack("<q", sb_raw[112:120])
        xp_data_base, = struct.unpack("<q", sb_raw[120:128])
        xp_desc_index, = struct.unpack("<I", sb_raw[136:140])
        xp_desc_len, = struct.unpack("<I", sb_raw[140:144])
        xp_data_index, = struct.unpack("<I", sb_raw[144:148])
        xp_data_len, = struct.unpack("<I", sb_raw[148:152])

        # 2. Checkpoint Selection & Checkpoint Map Lookup
        highest_xid = -1
        selected_nx = None

        for i in range(xp_desc_blocks):
            paddr = xp_desc_base + i
            raw = self.read_block(paddr)
            if not verify_checksum(raw):
                continue
            cksum, oid, xid, o_type = struct.unpack("<QQQI", raw[0:28])
            if (o_type & OBJECT_TYPE_MASK) == OBJ_CONTAINER_SUPERBLOCK and xid > highest_xid:
                highest_xid = xid
                selected_nx = raw

        if highest_xid == -1 or selected_nx is None:
            raise ValueError("No valid checkpoint found in descriptor ring")

        self.checkpoint_xid = highest_xid
        self.spaceman_oid, = struct.unpack("<Q", selected_nx[152:160])
        desc_index, = struct.unpack("<I", selected_nx[136:140])
        desc_len, = struct.unpack("<I", selected_nx[140:144])

        # Checkpoint map lookup for spaceman_oid across descriptor maps
        spaceman_paddr = None
        for i in range(desc_len):
            b_idx = (desc_index + i) % xp_desc_blocks
            paddr = xp_desc_base + b_idx
            raw = self.read_block(paddr)
            if not verify_checksum(raw):
                continue
            cksum, oid, xid, o_type = struct.unpack("<QQQI", raw[0:28])
            if (o_type & OBJECT_TYPE_MASK) == OBJ_CHECKPOINT_MAP and xid == highest_xid:
                flags, count = struct.unpack("<II", raw[32:40])
                for entry_idx in range(count):
                    c_type, c_sub, c_size, c_pad, c_fs_oid, c_oid, c_paddr = struct.unpack(
                        "<IIIIQQq", raw[40 + entry_idx * 40 : 40 + (entry_idx + 1) * 40]
                    )
                    if c_oid == self.spaceman_oid and c_fs_oid == 0:
                        spaceman_paddr = c_paddr
                        break
            if spaceman_paddr is not None:
                break

        if spaceman_paddr is None:
            raise ValueError(f"Could not resolve spaceman OID {self.spaceman_oid:#x}")

        # 3. Parse Space Manager (OBJ_SPACEMAN)
        sm_raw = self.read_block(spaceman_paddr)
        if not verify_checksum(sm_raw):
            raise ValueError("Space manager checksum mismatch")
        sm_cksum, sm_oid, sm_xid, sm_type = struct.unpack("<QQQI", sm_raw[0:28])
        if (sm_type & OBJECT_TYPE_MASK) != OBJ_SPACEMAN:
            raise ValueError(f"Invalid spaceman object type {sm_type:#x}")

        sm_blk_size, b_per_chunk, c_per_cib, cibs_per_cab = struct.unpack("<IIII", sm_raw[32:48])
        dev0_blk_cnt, dev0_chk_cnt, dev0_cib_cnt, dev0_cab_cnt, dev0_free_cnt, dev0_addr_off, dev0_res, dev0_res2 = struct.unpack(
            "<QQIIQIIQ", sm_raw[48:96]
        )
        dev1_blk_cnt, dev1_chk_cnt, dev1_cib_cnt, dev1_cab_cnt = struct.unpack("<QQII", sm_raw[96:120])
        struct_size, = struct.unpack("<I", sm_raw[292:296])

        if dev0_cab_cnt != 0 or dev1_blk_cnt != 0 or dev1_chk_cnt != 0 or dev1_cib_cnt != 0 or dev1_cab_cnt != 0:
            raise NotImplementedError("CAB and multi-device configurations are unsupported")

        # 4. Parse CIBs
        cib_addrs = []
        for i in range(dev0_cib_cnt):
            cib_paddr, = struct.unpack("<q", sm_raw[dev0_addr_off + i * 8 : dev0_addr_off + (i + 1) * 8])
            cib_addrs.append(cib_paddr)

        chunks_validated = []
        total_free_blocks = 0
        polarity = None # 0 = clear is free, 1 = set is free
        first_candidate_free = None
        have_clear_cand = False
        have_set_cand = False
        first_clear_info = None
        first_set_info = None

        for cib_idx, cib_paddr in enumerate(cib_addrs):
            cib_raw = self.read_block(cib_paddr)
            if not verify_checksum(cib_raw):
                raise ValueError(f"CIB {cib_idx} at paddr {cib_paddr} checksum mismatch")
            cib_cksum, cib_oid, cib_xid, cib_type = struct.unpack("<QQQI", cib_raw[0:28])
            if (cib_type & OBJECT_TYPE_MASK) != OBJ_SPACEMAN_CIB:
                raise ValueError(f"CIB {cib_idx} invalid object type {cib_type:#x}")
            cib_index, cib_chunk_info_count = struct.unpack("<II", cib_raw[32:40])
            if cib_index != cib_idx:
                raise ValueError(f"CIB index mismatch {cib_index} != {cib_idx}")

            for j in range(cib_chunk_info_count):
                ci_raw = cib_raw[40 + j * 32 : 40 + (j + 1) * 32]
                ci_xid, ci_addr, ci_blk_cnt, ci_free_cnt, ci_bm_addr = struct.unpack("<QQIIq", ci_raw)
                chunk_info = {
                    "cib_index": cib_idx,
                    "chunk_index": cib_idx * c_per_cib + j,
                    "addr": ci_addr,
                    "block_count": ci_blk_cnt,
                    "free_count": ci_free_cnt,
                    "bitmap_addr": ci_bm_addr,
                }

                if ci_bm_addr == 0:
                    # Unmapped chunk
                    if ci_free_cnt != ci_blk_cnt:
                        raise ValueError(f"Unmapped chunk {chunk_info['chunk_index']} free count != block count")
                    chunk_info["clear_count"] = ci_blk_cnt
                    chunk_info["set_count"] = 0
                    total_free_blocks += ci_free_cnt
                else:
                    bm_raw = self.read_block(ci_bm_addr)
                    clear_cnt = 0
                    set_cnt = 0
                    first_clear = None
                    first_set = None
                    for bit in range(ci_blk_cnt):
                        val = (bm_raw[bit >> 3] >> (bit & 7)) & 1
                        if val == 0:
                            clear_cnt += 1
                            if first_clear is None:
                                first_clear = bit
                        else:
                            set_cnt += 1
                            if first_set is None:
                                first_set = bit
                    chunk_info["clear_count"] = clear_cnt
                    chunk_info["set_count"] = set_cnt
                    chunk_info["first_clear"] = first_clear
                    chunk_info["first_set"] = first_set

                    if first_clear is not None and not have_clear_cand:
                        first_clear_info = (ci_addr + first_clear, chunk_info["chunk_index"], ci_bm_addr, first_clear)
                        have_clear_cand = True
                    if first_set is not None and not have_set_cand:
                        first_set_info = (ci_addr + first_set, chunk_info["chunk_index"], ci_bm_addr, first_set)
                        have_set_cand = True

                    if clear_cnt == ci_free_cnt and set_cnt != ci_free_cnt:
                        if polarity == 1:
                            raise ValueError(f"Polarity conflict at chunk {chunk_info['chunk_index']}")
                        polarity = 0
                    elif set_cnt == ci_free_cnt and clear_cnt != ci_free_cnt:
                        if polarity == 0:
                            raise ValueError(f"Polarity conflict at chunk {chunk_info['chunk_index']}")
                        polarity = 1
                    elif clear_cnt != ci_free_cnt or set_cnt != ci_free_cnt:
                        raise ValueError(f"Chunk {chunk_info['chunk_index']} bitmap counts do not match CIB free count")

                    total_free_blocks += ci_free_cnt

                chunks_validated.append(chunk_info)

        if polarity == 0 and have_clear_cand:
            first_candidate_free = first_clear_info
        elif polarity == 1 and have_set_cand:
            first_candidate_free = first_set_info

        return {
            "block_size": self.block_size,
            "block_count": self.block_count,
            "spaceman_oid": self.spaceman_oid,
            "spaceman_paddr": spaceman_paddr,
            "blocks_per_chunk": b_per_chunk,
            "chunks_per_cib": c_per_cib,
            "cib_count": dev0_cib_cnt,
            "chunk_count": dev0_chk_cnt,
            "device_free_count": dev0_free_cnt,
            "total_validated_free": total_free_blocks,
            "polarity": polarity,
            "candidate_free_block": first_candidate_free,
            "chunks": chunks_validated,
        }

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <apfs_image>")
        sys.exit(1)

    parser = APFSReferenceParser(sys.argv[1])
    try:
        res = parser.parse()
        print(f"Container Block Size: {res['block_size']}")
        print(f"Total Container Blocks: {res['block_count']}")
        print(f"Spaceman OID: {res['spaceman_oid']:#x} at block {res['spaceman_paddr']}")
        print(f"Blocks/Chunk: {res['blocks_per_chunk']}, Chunks/CIB: {res['chunks_per_cib']}")
        print(f"CIB Count: {res['cib_count']}, Total Chunks: {res['chunk_count']}")
        print(f"Device Free Count: {res['device_free_count']}, Total Validated Free: {res['total_validated_free']}")
        pol_str = "clear (0) is free" if res['polarity'] == 0 else ("set (1) is free" if res['polarity'] == 1 else "unknown")
        print(f"Bitmap Polarity: {pol_str}")
        if res['candidate_free_block']:
            blk, chk, bm, bit = res['candidate_free_block']
            print(f"Candidate Free Block: block={blk} (chunk={chk}, bitmap_block={bm}, bit_offset={bit})")
        print(f"Validation: {'PASSED' if res['device_free_count'] == res['total_validated_free'] else 'FAILED'}")
    finally:
        parser.close()

if __name__ == "__main__":
    main()
