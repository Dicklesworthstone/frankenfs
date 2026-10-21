# Native FAT create/replace publication

The disjoint replacement engine serves offline `replace`, `replace --create`,
and native file creation. Existing range writes continue to use their separate
allocation-reusing engine. The caller must retain exclusive writer ownership;
these checks do not exclude an unrelated writer or make FAT transactional.

A prepared replacement now rechecks every reserved cluster and captured old
successor before the first write. Stale allocation is a preflight refusal, not
an error discovered after overwriting a newly allocated owner's data. Scratch
for staging and directory publication is bounded and reserved before dirty state.

After synchronizing disjoint file data, the writer hashes the actual staged
clusters against the immutable source digest and checks every slack byte for
zero. Rehashing the input alone was not evidence that its output writes landed.
Only verified data may become a new FAT chain. Fresh readers then verify every
selected new link and captured old successor before any file entry is published.
Directory growth is followed by another link check because it can share FAT
sectors with these chains. Inactive FATs are not promoted to authorities.

Directory record changes use whole-sector read-modify-write, synchronization and
exact readback, including neighboring records. Old allocation remains retained
until native name resolution, exact directory metadata, chain identity and the
payload digest all verify. The new payload/chain is verified again after old
allocation reclamation before the final consistency and clean-state checks.

## Directory-record visibility

Creation prepares the complete new short entry with its deleted marker still
set. After synchronization and exact sector readback, a separate publication
changes only its first name byte. A reused slot therefore cannot become a new
live name while its stale head or length fields still identify a former object.
End-marker and long-name ordering still use the shared namespace staging path.

Replacement first publishes zero EOF with the original head, then publishes the
new head and metadata with EOF still zero, and only then exposes the final size.
Each necessary transition is synchronized and verified independently. FAT32's
separated high/low head words cannot expose another object through the old EOF
during that head transition. Mixed old/zero and zero/new size bytes remain
bounded by the respective old and new lengths. Already identical transitions
are skipped, including an already empty source or empty replacement.

These visibility barriers add synchronization costs. The earlier staging gates
add reads, not synchronization barriers. Neither is a measured performance
improvement. They detect the modeled dropped/torn or
misdirected writes at specified boundaries, not arbitrary media corruption or a
flush that lies about persistence. Interrupted mutation may require native
recovery; no rollback or atomic replacement is claimed. The original payload
clusters are not overwritten by this disjoint engine, even on failure, but that
is not a guarantee that their former namespace is automatically recoverable.
A failed replacement may now leave a zero-length file with retained allocation;
a failed creation may leave a deleted prepared record or orphaned long names.
Native checking/recovery is still required after uncertain mutation. Arbitrary
sector corruption and dishonest durability are outside the mixed-byte argument.

The constructed-image regressions exercise the production replacement engine,
not just a separate arithmetic model. They still require actual Rust execution
and independent native-tool qualification; test source is not runtime evidence.
