package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunPrintsVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), version) {
		t.Fatalf("output %q does not contain version %q", buf.String(), version)
	}
}
