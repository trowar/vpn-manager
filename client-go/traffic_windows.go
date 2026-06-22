//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func readNetworkTrafficCounters() (TrafficCounters, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		return TrafficCounters{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	count := int(table.NumEntries)
	rows := unsafe.Slice(&table.Table[0], count)
	var counters TrafficCounters
	for _, row := range rows {
		counters.RxBytes += row.InOctets
		counters.TxBytes += row.OutOctets
	}
	return counters, nil
}
