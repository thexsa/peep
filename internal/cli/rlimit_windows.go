//go:build windows

package cli

// tuneWorkerConcurrency is a no-op on Windows because Winsock does not impose
// a low POSIX RLIMIT_NOFILE descriptor cap on concurrent TCP sockets.
func tuneWorkerConcurrency(requestedWorkers int) int {
	if requestedWorkers < 1 {
		return 1
	}
	return requestedWorkers
}
