package main

// Windows Go does not support fsync on directory handles. File journals are
// synced, but power-loss durability also depends on the filesystem and OS.
func syncDirectory(path string) error { return nil }
