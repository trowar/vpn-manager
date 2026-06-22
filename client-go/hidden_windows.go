//go:build windows

package main

import "syscall"

const fileAttributeHidden = 0x2

func markHidden(path string) error {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(ptr, attrs|fileAttributeHidden)
}
