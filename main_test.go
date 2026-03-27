package main_test

import (
	"testing"

	main "go.home/watts-app-re"
)

func TestCodeVerifierToChallenge(t *testing.T) {
	in := "DM6nhvQSKnj72gkQQ5T1tCgCYGy5vdXnzdIQw3Bh46TX7pDvAcisyWDyt5UL3NQH8q4NoqMvRICQRmxCeDU3qHj8Jvciqo4RHcRiyjIlbB9q0k8LnUu8zHIdJHRLtk3J"
	expected := "Yj2RK4pCCe1WCHdPci80NvEw24Jf2esmCJjM0McD0lQ"
	actual := main.CodeVerifierToChallenge(in)
	if actual != expected {
		t.Errorf("expected main.CodeVerifierToChallenge(\"%v\") to be \"%v\" but got \"%v\"", in, expected, actual)
	}
}
