// Command service-vault is the VettID service vault: the component an
// application runs to connect with VettID members. It is a VMS v2 peer on
// the relay (VAULT-MESSAGING §6.4, §10.4) and serves the application a
// private HTTPS API and signed webhooks (MEMBER-SERVICE-PLAN §3, §7.2).
//
// Phase 0: only the version command exists.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: service-vault version\n")
	}
	flag.Parse()
	switch flag.Arg(0) {
	case "version":
		fmt.Println(version)
	default:
		flag.Usage()
		os.Exit(2)
	}
}
