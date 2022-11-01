//go:build darwin

package storage

import (
	"os"
	"syscall"
	"time"
)

func getFileTime(filename string) (time.Time, time.Time, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	stat := fi.Sys().(*syscall.Stat_t)
	cTime := time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec))

	mTime := fi.ModTime()

	return cTime, mTime, nil
}

func setFileTime(filename string, creationTime time.Time, modTime time.Time) error {
	err := os.Chtimes(filename, modTime, modTime)
	if err != nil {
		return err
	}
	return nil
}
