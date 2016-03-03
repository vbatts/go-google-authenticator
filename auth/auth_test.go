package auth

import (
	"fmt"
	"testing"
)

func TestGen(t *testing.T) {
	s, err := GenSecretKey("sha1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s) < 40 {
		t.Errorf("the key must be 40 characters or more. not %d", len(s))
	}
	fmt.Printf("GenSecretKey: %s\n", s)
}

func TestCode(t *testing.T) {
	var now int64 = 1379087253
	a := New("3a5bde8d0e4eb6887cb81bc7d51c3cec22b00ad1", false)

	code, exp, err := a.GetCode(0, now)
	if err != nil {
		t.Fatalf("Error in getting the packed byteOrder. %s", err)
	}
	if code != 535366 {
		t.Errorf("code (%d) did not match 535366", code)
	}
	if exp != 27 {
		t.Errorf("expiration (%d) did not match 27", exp)
	}
	fmt.Printf("Code:\t%d\nExp:\t%d\n", code, exp)
}
