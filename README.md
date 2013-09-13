go-google-authenticator
=======================

A command line tool to generate a ToTP token,
using the google-authenticator algorithm.


Installation
------------

This requires the golang compiler. Then run

	go get github.com/vbatts/go-google-authenticator


Flags can be provided, but also you can use a configuration file.
Default path expected is ~/.google-authenticator.yaml
Fields: salt (string), interval (int) and sha256 (bool)

Example:

	---
	salt: 91069284d7d521b19cc3ccf53a61aa51f47c4380
	interval: 30
	sha256: false


The salt is used when registering a profile with your authentication framework.
To generate a new random salt, there is a -gen flag.

	go-google-authenticator -gen

For services like LinOTP, this is the value needed for the seed for TOTP token.

Once this configuration file is set, or you use flags, then here is the output.

	> go-google-authenticator -salt 91069284d7d521b19cc3ccf53a61aa51f47c4380
	951670 (expires in 26s)

Enjoy!
