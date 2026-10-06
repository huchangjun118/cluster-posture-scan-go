package main

import "flag"

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
