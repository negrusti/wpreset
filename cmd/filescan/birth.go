package main

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func birthTime(ctx context.Context, path string) (*int64, string) {
	if runtime.GOOS != "linux" {
		return nil, "Linux birth time is only collected on Linux"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// GNU stat uses statx birth time when the kernel/filesystem expose it. %W
	// returns 0 when unknown; neither ctime nor mtime is a creation timestamp.
	data, err := exec.CommandContext(ctx, "stat", "--format=%W", "--", path).Output()
	if err != nil {
		return nil, "birth time unavailable (requires GNU stat and filesystem support)"
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || value == 0 {
		return nil, "filesystem/kernel does not expose birth time"
	}
	return &value, ""
}
