//go:build !race

package ballot

// raceEnabled: the race detector is on, and the slowest tests skip.
const raceEnabled = false
