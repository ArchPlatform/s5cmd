//go:build windows

package storage

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
)

type MetadataJob struct {
	Filename string
	UidId    string
	GidId    string
}

var lock = &sync.Mutex{}

type MetadataManager struct {
	processedFiles map[string]bool
	metadataLock   sync.Mutex
}

var metadataManager *MetadataManager

func GetMetadataManager() *MetadataManager {
	if metadataManager == nil {
		lock.Lock()
		defer lock.Unlock()
		if metadataManager == nil {
			metadataManager = &MetadataManager{
				processedFiles: make(map[string]bool),
				metadataLock:   sync.Mutex{},
			}
		}

	}
	return metadataManager
}

func (m *MetadataManager) Perform(filename string, uidSid, gidSid *windows.SID) error {
	m.metadataLock.Lock()
	defer m.metadataLock.Unlock()
	if _, ok := m.processedFiles[filename]; ok {
		return nil
	}

	m.processedFiles[filename] = true

	var err error
	privileges := []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"}
	err = winio.RunWithPrivileges(privileges,
		func() error {

			err = windows.SetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, uidSid, gidSid, nil, nil)
			if err != nil {
				return err
			}

			sd, err := windows.GetNamedSecurityInfo(
				filename,
				windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
			)
			dacl, _, err := sd.DACL()

			if err != nil {
				return err
			}

			err = windows.SetNamedSecurityInfo(
				filename,
				windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
				nil,
				nil,
				dacl,

				nil,
			)
			if err != nil {
				return err
			}

			return nil
		})

	return err
}

func GetFileTime(filename string) (time.Time, time.Time, time.Time, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}

	d := fi.Sys().(*syscall.Win32FileAttributeData)
	cTime := time.Unix(0, d.CreationTime.Nanoseconds())
	aTime := time.Unix(0, d.LastAccessTime.Nanoseconds())

	mTime := fi.ModTime()

	return aTime, mTime, cTime, nil
}

func SetFileTime(filename string, accessTime, modificationTime, creationTime time.Time) error {
	var err error
	if accessTime.IsZero() && modificationTime.IsZero() && creationTime.IsZero() {
		// Nothing recorded in s3. Return fast.
		return nil
	} else if accessTime.IsZero() {
		accessTime, _, _, err = GetFileTime(filename)
		if err != nil {
			return err
		}
	} else if modificationTime.IsZero() {
		_, modificationTime, _, err = GetFileTime(filename)
		if err != nil {
			return err
		}
	} else if creationTime.IsZero() {
		_, _, creationTime, err = GetFileTime(filename)
		if err != nil {
			return err
		}
	}

	aft := syscall.NsecToFiletime(accessTime.UnixNano())
	mft := syscall.NsecToFiletime(modificationTime.UnixNano())
	cft := syscall.NsecToFiletime(creationTime.UnixNano())

	fd, err := syscall.Open(filename, os.O_RDWR, 0775)
	if err != nil {
		return err
	}
	err = syscall.SetFileTime(fd, &cft, &aft, &mft)

	defer syscall.Close(fd)

	if err != nil {
		return err
	}
	return nil
}

// GetFileUserGroup will take a filename and return the userId and groupId associated with it.
//   On windows this is in the format of a SID, on linux/darwin this is in the format of a UID/GID.
func GetFileUserGroup(filename string) (userId, groupId string, err error) {
	sd, err := windows.GetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		return "", "", err
	}

	userSID, _, err := sd.Owner()
	groupSID, _, err := sd.Group()

	userId = userSID.String()
	groupId = groupSID.String()

	return userId, groupId, nil
}

// SetFileUserGroup will set the UserId and GroupId on a filename.
//   If the UserId/GroupId format does not match the platform, it will return an InvalidOwnershipFormatError.
// Windows expects the UserId/GroupId to be in SID format, Linux and Darwin expect it in UID/GID format.
func SetFileUserGroup(filename, userId, groupId string) error {
	if userId == "" && groupId == "" {
		return nil
	}

	var err error
	privileges := []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"}
	err = winio.RunWithPrivileges(privileges,
		func() error {
			var uidSid *windows.SID
			var gidSid *windows.SID
			if userId != "" {
				uidSid, err = StringAsSid(userId)
				if err != nil {
					return err
				}
			}

			if groupId != "" {
				gidSid, err = StringAsSid(groupId)
				if err != nil {
					return err
				}
			}

			metadataManager := GetMetadataManager()
			err = metadataManager.Perform(filename, uidSid, gidSid)
			if err != nil {
				return err
			}

			parentDir := filepath.Dir(filename)
			// Loop to process each parent directory up to the root
			for parentDir != "." && parentDir != "/" && parentDir != "\\" {
				err = metadataManager.Perform(parentDir, uidSid, gidSid)
				if err != nil {
					return err
				}
				// Move to the next parent directory
				nextPath := filepath.Dir(parentDir)
				if nextPath == parentDir {
					break
				}
				parentDir = nextPath
			}

			err = metadataManager.Perform(parentDir, uidSid, gidSid)
			if err != nil {
				return err
			}

			return nil

			// err = windows.SetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, uidSid, gidSid, nil, nil)
			// if err != nil {
			// 	return err
			// }

			// // handle parent dir

			// parentDir := filepath.Dir(filename)

			// err = windows.SetNamedSecurityInfo(parentDir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, uidSid, gidSid, nil, nil)
			// if err != nil {
			// 	return err
			// }

			// psd, err := windows.GetNamedSecurityInfo(
			// 	parentDir,
			// 	windows.SE_FILE_OBJECT,
			// 	windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
			// )
			// pdacl, _, err := psd.DACL()

			// if err != nil {
			// 	return err
			// }

			// err = windows.SetNamedSecurityInfo(
			// 	parentDir,
			// 	windows.SE_FILE_OBJECT,
			// 	windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			// 	nil,
			// 	nil,
			// 	pdacl,

			// 	nil,
			// )
			// if err != nil {
			// 	return err
			// }

			// // handle

			// sd, err := windows.GetNamedSecurityInfo(
			// 	filename,
			// 	windows.SE_FILE_OBJECT,
			// 	windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
			// )
			// dacl, _, err := sd.DACL()

			// if err != nil {
			// 	return err
			// }

			// err = windows.SetNamedSecurityInfo(
			// 	filename,
			// 	windows.SE_FILE_OBJECT,
			// 	windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			// 	nil,
			// 	nil,
			// 	dacl,

			// 	nil,
			// )
			// if err != nil {
			// 	return err
			// }

			// return nil
		})
	if err != nil {
		return err
	}

	return nil
}

func StringAsSid(principal string) (*windows.SID, error) {
	sid, err := windows.StringToSid(principal)
	if err != nil {
		if strings.Contains(err.Error(), "The security ID structure is invalid.") {
			sid, _, _, err = windows.LookupSID("", principal)
			if err != nil {
				return nil, &InvalidOwnershipFormatError{Err: err}
			}
		} else {
			return nil, &InvalidOwnershipFormatError{Err: err}
		}
	}
	return sid, nil
}

func StringSidAsName(strSID string) (name string, err error) {
	sid, err := StringAsSid(strSID)
	if err != nil {
		return "", err
	}
	name, _, _, err = sid.LookupAccount("")
	if err != nil {
		return "", err
	}
	return name, nil
}
