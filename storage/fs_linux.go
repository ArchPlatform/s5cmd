//go:build linux

package storage

import (
	"os"
	"syscall"
	"time"
)

func GetFileTime(filename string) (time.Time, time.Time, time.Time, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}

	stat := fi.Sys().(*syscall.Stat_t)
	cTime := time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
	aTime := time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))

	mTime := fi.ModTime()

	return aTime, mTime, cTime, nil
}

func SetFileTime(filename string, accessTime, modificationTime, creationTime time.Time) error {
	if accessTime.IsZero() && modificationTime.IsZero() {
		// Nothing recorded in s3. Return fast.
		return nil
	}
	var err error
	if accessTime.IsZero() {
		accessTime, _, _, err = GetFileTime(filename)
		if err != nil {
			return err
		}
	}
	if modificationTime.IsZero() {
		_, modificationTime, _, err = GetFileTime(filename)
		if err != nil {
			return err
		}
	}
	err = os.Chtimes(filename, accessTime, modificationTime)
	if err != nil {
		return err
	}
	return nil
}

// GetFileUserGroup will take a filename and return the userId and groupId associated with it.
//   On windows this is in the format of a SID, on linux/darwin this is in the format of a UID/GID.
func GetFileUserGroup(filename string) (username, group string, err error) {
	info, err := os.Stat(filename)
	if err != nil {
		return "", "", err
	}

	stat := info.Sys().(*syscall.Stat_t)

	username = strconv.Itoa(int(stat.Uid))
	group = strconv.Itoa(int(stat.Gid))
	return username, group, nil
}

// SetFileUserGroup will set the UserId and GroupId on a filename.
//   If the UserId/GroupId format does not match the platform, it will return an InvalidOwnershipFormatError.
// Windows expects the UserId/GroupId to be in SID format, Linux and Darwin expect it in UID/GID format.
func SetFileUserGroup(filename, uid, gid string) error {
	uidI, err := strconv.Atoi(uid)
	if err != nil {
		return &InvalidOwnershipFormatError{Err: err}
	}
	gidI, err := strconv.Atoi(gid)
	if err != nil {
		return &InvalidOwnershipFormatError{Err: err}
	}

	err = os.Lchown(filename, uidI, gidI)
	if err != nil {
		return err
	}
	return nil
}
