# branca

[![Build Status](https://travis-ci.org/hako/branca.svg?branch=master)](https://travis-ci.org/hako/branca) [![Go Report Card](https://goreportcard.com/badge/github.com/hako/branca)](https://goreportcard.com/report/github.com/hako/branca)
[![GoDoc](https://godoc.org/github.com/hako/branca?status.svg)](https://godoc.org/github.com/hako/branca) 

branca is a secure alternative to JWT, This implementation is written in pure Go (no cgo dependencies) and implements the [branca token specification](https://github.com/tuupola/branca-spec).

# Requirements

Go 1.13+

# Install

```
go get -u github.com/hako/branca
```

# Example

```go
package main

import (
	"fmt"
	"github.com/hako/branca"
)

func main() {
	b := branca.NewBranca("supersecretkeyyoushouldnotcommit") // This key must be exactly 32 bytes long.
	
	// Encode String to Branca Token.
	token, err := b.EncodeToString("Hello world!")
	if err != nil {
		fmt.Println(err)
	}
				
    //b.SetTTL(3600) // Uncomment this to set an expiration (or ttl) of the token (in seconds).
    //token = "87y8daMzSkn7PA7JsvrTT0JUq1OhCjw9K8w2eyY99DKru9FrVKMfeXWW8yB42C7u0I6jNhOdL5ZqL" // This token will be not allowed if a ttl is set.
	
	// Decode Branca Token.
	message, err := b.DecodeToString(token)
	if err != nil {
		fmt.Println(err) // token is expired.
		return
	}
	fmt.Println(token) // 87y8da....
	fmt.Println(message) // Hello world!
}
```

# Todo

Here are a few things that need to be done:

- [x] Remove cgo dependencies.
- [x] Move to a pure XChaCha20 algorithm in Go.
- [x] Add more tests than just acceptance tests.
- [x] Increase test coverage.
- [ ] Additional Methods. (Encode, Decode []byte)
- [ ] Performance benchmarks.
- [ ] More comments, examples and documentation.

# Contributing

Contributions are welcome! Fork this repo and add your changes and submit a PR.

If you would like to fix a bug, add a feature or provide feedback you can do so in the issues section.

You can run tests by runnning `go test`. Running `go test; go vet; golint` is recommended.

# License

MIT
