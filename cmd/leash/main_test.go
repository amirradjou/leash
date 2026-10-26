package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunPrintsVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := run(context.Background(), []string{"version"}, nil, &buf, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), version) {
		t.Fatalf("output %q does not contain version %q", buf.String(), version)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run(context.Background(), []string{"bogus"}, nil, nil, nil); err == nil {
		t.Fatal("unknown command accepted")
	}
}
