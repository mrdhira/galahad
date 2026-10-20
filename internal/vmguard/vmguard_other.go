//go:build !linux && !darwin && !windows

package vmguard

func gather() Signals { return Signals{} }
