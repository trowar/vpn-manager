package main

import "sync"

type virtualTunnelRuntime struct {
	done      chan struct{}
	closeFunc func()
	once      sync.Once
}

func (v *virtualTunnelRuntime) Close() {
	if v == nil {
		return
	}
	v.once.Do(func() {
		if v.closeFunc != nil {
			v.closeFunc()
		}
	})
}
