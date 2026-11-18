//go:build integration

package ballot

// SetEligibleCapForTest lets the integration tests (built with the
// integration tag, never the service) create proposals at up to
// PlannedMaxEligible members.
func (m *Manager) SetEligibleCapForTest(n int) { m.eligibleCap = n }
