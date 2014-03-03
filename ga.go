/*
Google-Authenticator implementation

This is a ToTP based token generator.
*/
package main

import (
	"flag"
	"fmt"
	"github.com/vbatts/go-google-authenticator/auth"
	"io/ioutil"
	"launchpad.net/goyaml"
	"os"
	"path/filepath"
)

func main() {
	var (
		f_debug       bool = false
		f_gen         bool = false
		f_gen_account string
		f_gen_key     string
		f_hash_sha256 bool = false
		f_interval    int
		f_salt        string
		f_config      string = filepath.Join(os.Getenv("HOME"), ".google-authenticator.yaml")
	)

	flag.BoolVar(&f_gen, "gen", f_gen,
		"generate a new TOTP salt")
	flag.StringVar(&f_gen_account, "account", f_gen_account,
		"when using -gen, set this as the account")
	flag.StringVar(&f_gen_key, "key", f_gen_key,
		"when using -gen, use this as the key instead of a random one")
	flag.BoolVar(&f_debug, "debug", f_debug,
		"debugging output")
	flag.BoolVar(&f_hash_sha256, "sha256", f_hash_sha256,
		"use sha26, instead of sha1")
	flag.IntVar(&f_interval, "int", f_interval,
		"time interval to use for the token")
	flag.StringVar(&f_salt, "salt", f_salt,
		"provide your own salt")
	flag.StringVar(&f_config, "config", f_config,
		"alternate configuration file to read")
	flag.Parse()
	auth.Debug = f_debug // set global debugging

	config_file, err := filepath.Abs(f_config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: finding config file (%s): %s\n", f_config, err)
		os.Exit(1)
	}
	if fi, err := os.Stat(config_file); err == nil && fi.Mode().IsRegular() {
		fh, err := os.Open(config_file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: opening %s: %s\n", config_file, err)
			os.Exit(1)
		}
		defer fh.Close()

		buf, err := ioutil.ReadAll(fh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: reading from %s: %s\n", config_file, err)
			os.Exit(1)
		}
		config := Config{}
		err = goyaml.Unmarshal(buf, &config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: parsing yaml in %s: %s\n", config_file, err)
			os.Exit(1)
		}
		if f_debug {
			fmt.Printf("Read-in config:\t%#v\n", config)
		}

		// Set the variables!
		if config.Interval != 0 && f_interval != 0 {
			// this is if the configuration file has an interval,
			// and they didn't pass a flag
			f_interval = config.Interval
		}
		if len(config.Salt) > 0 && len(f_salt) == 0 {
			// again, is in config, and no flag provided
			f_salt = config.Salt
		}
		if config.Sha256 && !f_hash_sha256 {
			// again, is in config, and no flag provided
			f_hash_sha256 = config.Sha256
		}
	} else if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}

	if f_gen {
		if len(f_gen_key) == 0 {
			if f_hash_sha256 {
				f_gen_key, err = auth.GenSecretKey("sha256")
			} else {
				f_gen_key, err = auth.GenSecretKey("sha1")
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
				os.Exit(1)
			}
		}
		if len(f_gen_account) == 0 {
			f_gen_account = os.Getenv("USER")
		}
		fmt.Printf("salt: %s\n%s\n", f_gen_key, auth.QrCode(f_gen_account, f_gen_key))
		return
	}

	if len(f_salt) == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: must provide a salt!\n")
		os.Exit(1)
	}

	a := auth.New(f_salt, f_hash_sha256)
	if f_interval != 0 {
		a.Interval = f_interval
	}

	j, x, err := a.GetCodeCurrent()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
	// this number is to be padded with zeros, always 6 digits long
	fmt.Printf("%06d (expires in %ds)\n", j, x)
}

type Config struct {
	Salt     string `yaml:"salt,omitempty"`
	Interval int    `yaml:"interval,omitempty"`
	Sha256   bool   `yaml:"sha256,omitempty"`
}
