// Package gopipt supports basic parsing of iptables rules.
package gopipt

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Parse parses the output of a table output from:
//
//   iptables [-t <table>] -L -n -v -x [--line-numbers]
func Parse(r ReadLiner) (*Table, error) {
	t := &Table{}
	var s matcher
	s = matchChain
	var err error
	for {
		var line string
		if line, err = r.ReadLine(); err != nil {
			break
		}
		line = strings.TrimRight(line, " \r\n")
		if s, err = s(line, false, t); err != nil {
			return nil, fmt.Errorf("%v, while parsing line: %q", err, line)
		}
	}
	if err != io.EOF {
		return nil, err
	}
	if s, err = s("", true, t); err != nil {
		return nil, fmt.Errorf("%v, when encountered EOF", err)
	}
	return t, nil
}

type matcher func(line string, eof bool, t *Table) (matcher, error)

var (
	builtinChainRx = regexp.MustCompile(`^Chain (?P<chain>[^ ]+) \(policy (?P<policy>[^ ]+) (?P<packets>[0-9]+) packets, (?P<bytes>[0-9]+) bytes\)$`)
	userChainRx    = regexp.MustCompile(`^Chain (?P<chain>[^ ]+) \((?P<refs>[0-9]+) references\)$`)
)

func matchChain(line string, eof bool, t *Table) (matcher, error) {
	if eof {
		return matchTerminal, nil
	}
	var err error
	if m := builtinChainRx.FindStringSubmatch(line); m != nil {
		c := &Chain{
			Name:    m[1],
			Policy:  m[2],
			HasCtrs: true,
		}
		if c.PacketCtr, err = strconv.ParseInt(m[3], 10, 64); err != nil {
			return matchTerminal, err
		}
		if c.ByteCtr, err = strconv.ParseInt(m[4], 10, 64); err != nil {
			return matchTerminal, err
		}
		t.Chains = append(t.Chains, c)
		return matchHeader, nil
	}
	if m := userChainRx.FindStringSubmatch(line); m != nil {
		c := &Chain{
			Name:      m[1],
			HasRefCnt: true,
		}
		if c.RefCnt, err = strconv.ParseInt(m[2], 10, 64); err != nil {
			return matchTerminal, err
		}
		t.Chains = append(t.Chains, c)
		return matchHeader, nil
	}
	return matchTerminal, errors.New("failed to match chain line")
}

var headerRx = regexp.MustCompile(`^num *pkts *bytes *target *prot *opt *in *out *source *destination$`)

func matchHeader(line string, eof bool, t *Table) (matcher, error) {
	if !eof && headerRx.MatchString(line) {
		return matchRule, nil
	}
	return matchTerminal, errors.New("failed to match rules header line")
}

var ruleRx = regexp.MustCompile(`^(?P<num>[0-9]+)? *(?P<pkts>[0-9]+) *(?P<bytes>[0-9]+) (?P<target>[^ ]+) *(?P<prot>[^ ]+) *(?P<opt>[^ ]+) *(?P<in>[^ ]+) *(?P<out>[^ ]+) *(?P<source>[^ ]+) *(?P<destination>[^ ]+) *(?P<match>.*?) *(?:/\* (?P<comment>.*?) \*/)?$`)

func matchRule(line string, eof bool, t *Table) (matcher, error) {
	if eof {
		return matchTerminal, nil
	}
	if line == "" {
		return matchChain, nil
	}
	if m := ruleRx.FindStringSubmatch(line); m != nil {
		if len(t.Chains) < 1 {
			// This should never happen if the state machine is set up correctly. If
			// it does, it indicates a bug in the code.
			return matchTerminal, errors.New("matched a rule, when no chains exist")
		}
		c := t.Chains[len(t.Chains)-1]
		r := &Rule{
			Target:      m[4],
			Protocol:    m[5],
			Option:      m[6],
			In:          m[7],
			Out:         m[8],
			Source:      m[9],
			Destination: m[10],
			Match:       m[11],
			Comment:     m[12],
		}
		var err error
		if r.PacketCtr, err = strconv.ParseInt(m[2], 10, 64); err != nil {
			return matchTerminal, err
		}
		if r.ByteCtr, err = strconv.ParseInt(m[3], 10, 64); err != nil {
			return matchTerminal, err
		}
		c.Rules = append(c.Rules, r)
		return matchRule, nil
	}
	return matchTerminal, errors.New("failed to match rules line")
}

func matchTerminal(line string, eof bool, t *Table) (matcher, error) {
	// This should never be called.
	return matchTerminal, errors.New("terminal state machine state")
}
