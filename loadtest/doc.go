// Package loadtest runs SIEMLite end to end under concurrent and heavy load.
//
// The stress test runs with the normal test suite. The load tests are
// skipped unless SIEMLITE_LOAD is set:
//
//	SIEMLITE_LOAD=ci    go test ./loadtest -run Load -v   # ~2 minutes, every commit
//	SIEMLITE_LOAD=small go test ./loadtest -run Load -v   # ~6 minutes
//	SIEMLITE_LOAD=hard SIEMLITE_LOAD_FOR=30m go test ./loadtest -run Load -v -timeout 3h
//
// The hard run is sized to take about SIEMLITE_LOAD_FOR: 5m, 30m or 2h
// (millions of events: about 0.6, 3 and 20).
//
// Each load test reports its numbers and fails if they fall below a floor.
// Give the hard run space in TMPDIR (a RAM-backed /tmp may be too small):
// about 2 GB for 5m, 10 GB for 30m and 30 GB for 2h.
package loadtest
