//go:build linux

package storage

import (
	"os"
	"syscall"
	"time"
)

func getFileTime(filename string) (time.Time, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return time.Time{}, err
	}

	var cTime time.Time

	stat := fi.Sys().(*syscall.Stat_t)
	cTime = time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))

	return cTime, nil
}

func setFileTime(filename string, creationTime time.Time, modTime time.Time) error {
	fd, err := syscall.Open(filename, os.O_RDWR, 0775)
	if err != nil {
		return err
	}

	err := os.Chtimes(filename, modTime, modTime)
	if err != nil {
		return err
	}
	return nil
}
