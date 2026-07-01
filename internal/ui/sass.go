package ui

import (
	"math/rand"
	"sync"
)

// sassTracker ensures no sarcastic remark is repeated within a single
// output render pass. Call Reset() at the start of each render pass,
// then use Pick() to get a unique remark from a pool.
type sassTracker struct {
	mu   sync.Mutex
	used map[string]bool
}

// globalSass is the singleton tracker for the current render pass.
var globalSass = &sassTracker{used: make(map[string]bool)}

// ResetSass clears the used remarks tracker. Call this at the beginning
// of each top-level render (e.g., start of scan output).
func ResetSass() {
	globalSass.mu.Lock()
	defer globalSass.mu.Unlock()
	globalSass.used = make(map[string]bool)
}

// PickSass selects a random remark from the pool that hasn't been used
// yet in this render pass. If all remarks in the pool have been used,
// it resets and picks freely (better than returning nothing).
func PickSass(pool []string) string {
	if len(pool) == 0 {
		return ""
	}

	globalSass.mu.Lock()
	defer globalSass.mu.Unlock()

	// Build list of unused options
	var available []string
	for _, s := range pool {
		if !globalSass.used[s] {
			available = append(available, s)
		}
	}

	// If everything's been used, pick from the full pool
	if len(available) == 0 {
		available = pool
	}

	pick := available[rand.Intn(len(available))]
	globalSass.used[pick] = true
	return pick
}
