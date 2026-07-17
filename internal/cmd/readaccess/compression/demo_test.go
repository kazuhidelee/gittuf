// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package compression

import (
	"strings"
	"testing"
)

func TestReconstructUsesDeltaWhenACLMatches(t *testing.T) {
	base := []byte(strings.Repeat("hello brave new world\n", 64))
	target := []byte(strings.Replace(string(base), "brave", "very-brave", 1))

	b, err := buildBundle("secret.txt", base, target, []string{"alice"}, []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	if b.manifest.DeltaArtifactFile == "" {
		t.Fatal("expected delta artifact")
	}

	got, mode, err := reconstructForPrincipal(b, "alice", base)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "delta" {
		t.Fatalf("expected delta mode, got %q", mode)
	}
	if string(got) != string(target) {
		t.Fatalf("unexpected reconstruction: %q", got)
	}
}

func TestReconstructFallsBackToFullForNewReaderWhenACLChanges(t *testing.T) {
	base := []byte("v1 secret\n")
	target := []byte("v2 secret\n")

	b, err := buildBundle("secret.txt", base, target, []string{"alice"}, []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if b.manifest.DeltaArtifactFile == "" {
		t.Fatal("expected delta artifact")
	}
	if len(b.manifest.DeltaPrincipals) != 1 || b.manifest.DeltaPrincipals[0] != "alice" {
		t.Fatalf("unexpected delta principals: %#v", b.manifest.DeltaPrincipals)
	}

	got, mode, err := reconstructForPrincipal(b, "bob", base)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "full" {
		t.Fatalf("expected full mode, got %q", mode)
	}
	if string(got) != string(target) {
		t.Fatalf("unexpected reconstruction: %q", got)
	}
}

func TestReconstructUsesDeltaForOverlapReaderWhenACLChanges(t *testing.T) {
	base := []byte("v1 secret\n")
	target := []byte("v2 secret\n")

	b, err := buildBundle("secret.txt", base, target, []string{"alice"}, []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}

	got, mode, err := reconstructForPrincipal(b, "alice", base)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "delta" {
		t.Fatalf("expected delta mode, got %q", mode)
	}
	if string(got) != string(target) {
		t.Fatalf("unexpected reconstruction: %q", got)
	}
}
