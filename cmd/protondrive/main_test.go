package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("unable to determine home directory: %v", err)
	}

	tmp := filepath.Join(os.TempDir(), "protondrive-path")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "noTilde", input: tmp, want: tmp},
		{name: "tildeOnly", input: "~", want: home},
		{name: "tildeSlash", input: "~/", want: home},
		{name: "tildeNested", input: "~/ProtonDrive/sub", want: filepath.Join(home, "ProtonDrive", "sub")},
		{name: "tildeBackslash", input: "~\\ProtonDrive", want: filepath.Join(home, "ProtonDrive")},
		{name: "tildeUsername", input: "~someone", want: "~someone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandPath(tt.input); got != tt.want {
				t.Fatalf("expandPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
