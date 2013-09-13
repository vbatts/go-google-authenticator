/*
Google-Authenticator implementation
*/
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"

  "github.com/vbatts/go-google-authenticator/auth"
)

func main() {
	var (
		f_gen         bool = false
		f_hash_sha256 bool = false
		f_interval    int  = 30
		f_salt        string
		f_debug       bool = false
	)

	flag.BoolVar(&f_gen, "gen", f_gen,
		"generate a new TOTP salt")
	flag.BoolVar(&f_debug, "debug", f_debug,
		"debugging output")
	flag.BoolVar(&f_hash_sha256, "sha256", f_hash_sha256,
		"use sha26, instead of sha1")
	flag.IntVar(&f_interval, "int", f_interval,
		"time interval to use for the token")
	flag.StringVar(&f_salt, "salt", f_salt,
		"provide your own salt")
	flag.Parse()
	auth.Debug = f_debug // set global debugging

	if f_gen {
		fmt.Printf("ERROR: not implemented yet\n")
		return
	}

	if len(f_salt) == 0 {
		fmt.Printf("ERROR: must provide a salt!\n")
		return
	}

	h_func := func() hash.Hash {
		if f_hash_sha256 {
			return sha256.New()
		}
		return sha1.New()
	}

	k := bytes.NewBufferString(f_salt).Bytes()
	a := auth.Authenticator{
		Interval: f_interval,
		Hash:     hmac.New(h_func, k),
	}

	j, x, err := a.GetCodeCurrent()
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
	}
	fmt.Printf("%d (expires in %ds)\n", j, x)
}

var (
	// TODO make a generator. on ruby, something like:
	// > rand(999999999999999999999999999999).to_s(16) * 2
)

