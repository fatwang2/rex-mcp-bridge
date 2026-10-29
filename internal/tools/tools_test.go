package tools

import "testing"

func TestTail(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		n, max    int
		want      string
		truncated bool
	}{
		{"fits", "a\nb\nc\n", 5, 100, "a\nb\nc", false},
		{"last lines", "a\nb\nc\nd", 2, 100, "c\nd", true},
		{"byte cap starts at a line", "aaaa\nbbbb\ncccc", 10, 7, "cccc", true},
		{"empty", "", 5, 100, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated := Tail(tt.in, tt.n, tt.max)
			if got != tt.want || truncated != tt.truncated {
				t.Errorf("Tail(%q, %d, %d) = %q, %v; want %q, %v", tt.in, tt.n, tt.max, got, truncated, tt.want, tt.truncated)
			}
		})
	}
}
