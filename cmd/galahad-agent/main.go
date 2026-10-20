package main

import (
	"os"

	"github.com/mrdhira/galahad/internal/agent"
)

func main() {
	os.Exit(agent.Run(os.Args[1:], os.Stdout, os.Stderr))
}
