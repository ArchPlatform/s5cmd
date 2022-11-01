//go:build windows

package storage

import (
	"os"
	"syscall"
	"time"
)

func GetFileTime(filename string) (time.Time, time.Time, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	d := fi.Sys().(*syscall.Win32FileAttributeData)
	cTime := time.Unix(0, d.CreationTime.Nanoseconds())

	mTime := fi.ModTime()

	return cTime, mTime, nil
}

func SetFileTime(filename string, creationTime time.Time, modTime time.Time) error {
	fd, err := syscall.Open(filename, os.O_RDWR, 0775)
	if err != nil {
		return err
	}

	cft := syscall.NsecToFiletime(int64(creationTime.Nanosecond()))
	mft := syscall.NsecToFiletime(int64(modTime.Nanosecond()))
	err = syscall.SetFileTime(fd, &cft, &mft, &mft)
	if err != nil {
		return err
	}
	return nil
}
