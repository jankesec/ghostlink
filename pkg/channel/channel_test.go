package channel

import "testing"

func TestRegisteredChannelsAreSorted(t *testing.T) {
	types := RegisteredChannels()
	for i := 1; i < len(types); i++ {
		if types[i-1] > types[i] {
			t.Fatalf("registry is not sorted: %q appears before %q", types[i-1], types[i])
		}
	}
}
