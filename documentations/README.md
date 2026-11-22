# APFS implementation notes

These pages describe the current NetBSD APFS implementation and provide a
workflow for investigating a stalled create or write. They are implementation
notes, not an APFS format specification.

- [Current feature coverage](features.md): implemented code paths, current
  limitations, and features that are not supported.
- [Space Manager, bitmaps, and filesystem operations](spaceman-and-filesystem.md):
  how block accounting and filesystem mutations fit together.
- [Create and write paths](write-path.md): VOP entry points, transaction flow,
  copy-on-write metadata, and the difference between creating an empty file
  and writing file data.
- [Locking and stall diagnosis](locking-and-stalls.md): lock ownership,
  allocation flow, known wait points, and how to interpret the traces.
- [Browser guide](web/index.html): standalone HTML pages for learning the
  implementation in a browser.

`APFS_DEBUG` defaults to enabled in `sys/fs/apfs/apfs.h` while this
implementation is under active development. APFS trace messages use the
`apfs_trace:` prefix. Set `APFS_DEBUG` to `0` to compile those calls away.
