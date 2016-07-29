package gopipt

import (
	"bytes"
	"fmt"
)

// Table represents an iptables table.
type Table struct {
	Chains []*Chain
}

func (t *Table) String() string {
	w := &bytes.Buffer{}
	fmt.Fprintf(w, "Table {\n")
	for _, c := range t.Chains {
		c.stringTo(w)
	}
	fmt.Fprintf(w, "}\n")
	return w.String()
}

// Chain represents an iptables chain.
type Chain struct {
	Name      string
	Policy    string
	PacketCtr int64
	ByteCtr   int64
	RefCnt    int64
	Rules     []*Rule
	HasCtrs   bool
	HasRefCnt bool
}

func (c *Chain) stringTo(w *bytes.Buffer) {
	fmt.Fprintf(w, "Chain [ name=%q", c.Name)
	if c.Policy != "" {
		fmt.Fprintf(w, " policy=%q", c.Policy)
	}
	if c.HasCtrs {
		fmt.Fprintf(w, " packets=%d bytes=%d", c.PacketCtr, c.ByteCtr)
	}
	if c.HasRefCnt {
		fmt.Fprintf(w, " references=%d", c.RefCnt)
	}
	fmt.Fprintf(w, " ] {\n")
	for _, r := range c.Rules {
		fmt.Fprintf(w, "%v\n", r)
	}
	fmt.Fprintf(w, "}\n")
}

// Rule represents an individual rule in an iptables chain.
type Rule struct {
	PacketCtr   int64
	ByteCtr     int64
	Target      string
	Protocol    string
	Option      string
	In          string
	Out         string
	Source      string
	Destination string
	Match       string
	Comment     string
}

func (r *Rule) String() string {
	return fmt.Sprintf("packets=%d bytes=%d target=%q proto=%q option=%q in=%q out=%q src=%q dest=%q match=%q comment=%q",
		r.PacketCtr, r.ByteCtr, r.Target, r.Protocol, r.Option, r.In, r.Out, r.Source, r.Destination, r.Match, r.Comment)
}
