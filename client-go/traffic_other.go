//go:build !windows

package main

func readNetworkTrafficCounters() (TrafficCounters, error) {
	return TrafficCounters{}, nil
}
