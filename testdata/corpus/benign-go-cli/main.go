// Command benign-go-cli prints a greeting. It is a harmless corpus fixture.
package main

import (
	"flag"
	"fmt"
)

func main() {
	name := flag.String("name", "world", "who to greet")
	flag.Parse()
	fmt.Printf("hello, %s\n", *name)
}
