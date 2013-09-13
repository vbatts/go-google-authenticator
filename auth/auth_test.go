package auth

import (
	"fmt"
	"testing"
)

func TestGen(t *testing.T) {

	s := GenSecretKey()
	if len(s) < 40 {
		t.Errorf("the key must be 40 characters or more. not %d", len(s))
	}
	fmt.Printf("GenSecretKey: %s\n", s)
}
