//go:build !unix

package backup

func freeBytes(string) int64 { return -1 }
