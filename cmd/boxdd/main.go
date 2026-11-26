// Command boxdd is the daemon of experimental/boxdd as upstream builds it (niko: the daemon is a package, so that a
// program can add its own services; this program adds none).
package main

import "github.com/sagernet/sing-box/experimental/boxdd"

func main() {
	boxdd.Main(boxdd.Options{DevelopmentListen: true})
}
