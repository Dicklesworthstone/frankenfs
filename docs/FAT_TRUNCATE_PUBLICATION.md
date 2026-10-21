# Native FAT truncation publication

Native shrinking keeps the retained prefix in its existing clusters. It does
not need a second file-sized allocation. The retained payload digest, selected
FAT copies, final record, chain cut, allocation accounting and complete namespace
are checked before clean state. Detached clusters are freed only after the
shorter record and retained chain/payload have passed readback.

A shorter length cannot always be safely published as one little-endian update.
For example, changing 65,536 to 65,535 can leave 131,071 after only the first two
size bytes are written. An otherwise valid preallocated chain could then expose
bytes beyond the original EOF. FAT has no native transaction to hide that result.

When a shrinking size introduces set bits, the writer first publishes
`old_size & new_size` while keeping the original head and other record fields.
It synchronizes and reads back the complete containing sector before publishing
the final record. Old-to-intermediate only clears size bits; intermediate-to-new
only sets size bits. Any mixture of those old/new size bytes stays within the
appropriate old or final EOF. When the new size only clears bits and keeps the
same head, the extra publication is unnecessary and is skipped.

Truncation to zero always synchronizes and verifies zero EOF with the old head
before clearing the first-cluster fields. This matters especially for FAT32,
whose high and low cluster words are separated in the directory record. No chain
is cut or reclaimed after a failed guard write, synchronization or readback.
The existing mounted-operation quarantine applies to these failures too.

This is ordered native mutation, **not crash atomicity**. An interrupted shrink
may leave the intermediate length (possibly zero), excess allocation, conflicting
FAT copies or damaged metadata requiring explicit recovery. Original EOF is not
promised recoverable. The mixed-byte argument is not protection against arbitrary
media corruption, a dishonest flush, or writes reordered across a successful
verified durability barrier. No rollback, cleanup writes or secure erasure is
performed. Existing retained-payload verification and later consistency checks
are unchanged. The added barrier is paid only when the guarded transition is
needed; no measured performance claim is made.

The regressions exercise production truncation, setattr and truncating open on
constructed images, plus pending/durable write faults. Authored tests and a
separate arithmetic model are not evidence that Rust compilation, kernel FUSE,
or native filesystem interchange has been qualified.
