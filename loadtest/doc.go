// Package loadtest runs SIEMLite end to end under concurrent and heavy load.
//
// The stress test runs with the normal test suite. The load tests are
// skipped unless SIEMLITE_LOAD is set:
//
//	SIEMLITE_LOAD=ci    go test ./loadtest -run Load -v   # ~2 minutes, every commit
//	SIEMLITE_LOAD=small go test ./loadtest -run Load -v   # ~6 minutes
//	SIEMLITE_LOAD=hard  go test ./loadtest -run Load -v -timeout 90m
//
// Each load test reports its numbers and fails if they fall below a floor.
// The hard run builds a 5 million event database: give it about 10 GB of
// space in TMPDIR (a RAM-backed /tmp may be too small).
package loadtest
