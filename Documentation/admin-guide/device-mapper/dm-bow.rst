================================
dm-bow: backup using trimmed space
================================

The ``bow`` target keeps a rollback log and backups in space marked free by
filesystem discard requests. It exposes the same logical contents while moving
its log and backups as necessary. Userspace performs rollback after unmounting
and removing the target; the kernel does not implement the rollback utility.

The target arguments are::

    <backing device> [<number of options> [block_size:<bytes>]]

``block_size`` must be a power of two between 512 and 4096. The default is the
backing device's logical block size. Android fs_mgr selects 4096 when stacking
below dm-default-key to keep relocation aligned to encryption data units. The
selected size also constrains the target's logical I/O alignment.

The ``bow/state`` attribute under the mapped disk's sysfs directory reports one
of three states. Only the transitions 0 to 1 and 1 to 2 are permitted:

0: collect free space
    Discard requests mark free ranges without issuing physical discards.
    Writes remove affected ranges from the free list. Userspace normally issues
    FITRIM on the mounted filesystem before switching to state 1.

1: checkpoint
    Before overwriting original data or an existing backup, the target copies
    it into free space and persists a log entry. The first block holds the log;
    its live filesystem contents are relocated into a separate free block.
    The target redirects reads and writes of logical sector zero to that live
    block. Discard requests are acknowledged without changing the checkpoint.
    Exhausting backup space fails the affected write with ENOSPC.

2: committed
    The target copies the latest live sector-zero contents back over the log
    and becomes a passthrough device. Rollback is no longer available. Range
    metadata is retained until the target is destroyed.

``bow/free`` reports the remaining tracked free space in bytes. Free space
consumed by backups is subtracted from this value.

Checkpoint-sensitive I/O, including flushes and sector-zero access, runs on an
ordered workqueue and waits for lower I/O completion. State changes stop new
queue submissions and drain the queue before updating the log or state.
Nonzero reads and committed I/O retain their passthrough paths. This favors
checkpoint ordering over concurrent write throughput.

A backup/log I/O failure or incomplete state transition blocks further I/O and
state changes through that target. A failed checkpoint must not be silently
committed. Ordinary backup-space exhaustion during a write can still be
resolved by committing the checkpoint. No successful return guarantees recovery
from underlying storage that has failed to preserve already written data.

The log consists of a versioned header, a sequence number, the live sector-zero
location and entries recording source sector, destination sector, size in bytes
and checksum. When the log fills, it is backed up and a new log begins with the
entry describing that backup. Userspace rollback replays these records in reverse.
