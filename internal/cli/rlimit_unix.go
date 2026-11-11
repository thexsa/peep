//go:build !windows

package cli

import "syscall"

// tuneWorkerConcurrency raises the soft RLIMIT_NOFILE toward 4096 when allowed
// by the OS hard limit and clamps requestedWorkers safely below the effective
// soft limit so full-port scans never fail silently with EMFILE (e.g. macOS default 256).
func tuneWorkerConcurrency(requestedWorkers int) int {
	if requestedWorkers < 1 {
		requestedWorkers = 1
	}

	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return requestedWorkers
	}

	const targetSoft = 4096
	if rlim.Cur > 0 && rlim.Cur < targetSoft {
		updated := rlim
		updated.Cur = targetSoft
		if rlim.Max > 0 && rlim.Max < targetSoft {
			updated.Cur = rlim.Max
		}
		if updated.Cur > rlim.Cur {
			if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &updated); err == nil {
				_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim)
			}
		}
	}

	// Reserve headroom for stdin/stdout/stderr, DNS resolver sockets, and runtime fds.
	if rlim.Cur > 0 && rlim.Cur < 65535 {
		safeMax := int(rlim.Cur) - 64
		if safeMax < 32 {
			safeMax = int(rlim.Cur) / 2
			if safeMax < 8 {
				safeMax = 8
			}
		}
		if requestedWorkers > safeMax {
			return safeMax
		}
	}

	return requestedWorkers
}
