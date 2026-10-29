package keystore

// BallotCopyKeyName is the record holding the key the write-once copy of
// accepted ballots is sealed under (BALLOT-PROTOCOL §6 "Durability"). It
// is apart from the record key: the record key's rotation reseals the
// table's records and then deletes the older versions, but an item of
// the copy is written once and can't be resealed, so its key is never
// rotated away.
const BallotCopyKeyName = "ballot-copy-key"
