package storage

// SetAfterAllocate makes db run f after numbering each batch and before
// storing it, so a test can hold a batch in flight.
func SetAfterAllocate(db *DB, f func()) { db.days.afterAllocate = f }
