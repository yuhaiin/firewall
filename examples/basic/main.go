// Command basic installs a persistent, default-allow policy only with -apply.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"time"

	fw "github.com/yuhaiin/firewall"
)

func main() {
	apply := flag.Bool("apply", false, "install native policy; requires platform permissions/setup")
	remove := flag.Bool("remove", false, "explicitly remove this example's owned policy")
	flag.Parse()
	if !*apply && !*remove {
		fmt.Println("No native state changed. Use -apply or -remove after reading platform setup.")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	c, err := open(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			log.Print(err)
		}
	}()
	caps, err := c.Capabilities(ctx)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Printf("Backend: %s; available=%t permitted=%t\n", caps.Backend, caps.Available, caps.Permitted)
	if *remove {
		if err = c.Remove(ctx); err != nil {
			log.Print(err)
		}
		return
	}
	events, err := c.Events(ctx)
	if err != nil {
		log.Print(err)
		return
	}
	go func() {
		for e := range events {
			fmt.Printf("%s generation=%d lost=%d %s\n", e.Kind, e.Revision.Generation, e.Dropped, e.Reason)
		}
	}()
	p := fw.Policy{Lifetime: fw.Persistent, Defaults: map[fw.Direction]fw.Action{fw.Outbound: fw.Allow}, Rules: []fw.Rule{{ID: "block-documentation-network", Priority: 100, Direction: fw.Outbound, Family: fw.IPv4, Action: fw.Drop, When: fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: netip.MustParsePrefix("192.0.2.0/24")})}}}
	revision, err := c.Apply(ctx, p)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Printf("Installed generation %d\n", revision.Generation)
	// Idempotent reapplication preserves the generation. For an actual update,
	// change a rule and Apply the complete desired policy again.
	if _, err = c.Apply(ctx, p); err != nil {
		log.Print(err)
		return
	}
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, err := c.Current(shutdown)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Printf("Persistent generation %d remains after Close; use -remove explicitly.\n", state.Revision.Generation)
}
