//go:build windows

package storage

import (
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Load the SetEntriesInAclW Win API function
var (
	modadvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procSetEntriesInAclW = modadvapi32.NewProc("SetEntriesInAclW")
)

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

	var fd syscall.Handle
	fi, err := os.Stat(filename)
	if fi.IsDir() {
		fd, err = getDirectoryHandle(filename)
	} else {
		fd, err = syscall.Open(filename, os.O_RDWR, 0775)
	}
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

func getDirectoryHandle(filename string) (syscall.Handle, error) {
	pathp, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	h, e := syscall.CreateFile(pathp,
		syscall.FILE_WRITE_ATTRIBUTES, syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return syscall.InvalidHandle, e
	}
	return h, nil
}

// GetFileUserGroup will take a filename and return the userId and groupId associated with it.
//
//	On windows this is in the format of a SID, on linux/darwin this is in the format of a UID/GID.
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
//
//	If the UserId/GroupId format does not match the platform, it will return an InvalidOwnershipFormatError.
//
// Windows expects the UserId/GroupId to be in SID format, Linux and Darwin expect it in UID/GID format.
func SetFileUserGroup(filename, userId, groupId string) error {
	if userId == "" || groupId == "" {
		return &InvalidOwnershipFormatError{
			Err: fmt.Errorf(
				"invalid userID or groupID for file: \"%s\", \"%s\" (%s)", userId, groupId, filename,
			),
		}
	}
	var err error
	privileges := []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"}
	if err := winio.EnableProcessPrivileges(privileges); err != nil {
		return err
	}
	defer winio.DisableProcessPrivileges(privileges)

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

	err = windows.SetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, uidSid, gidSid, nil, nil)
	if err != nil {
		return err
	}

	err = addCreatorOwnerAclToFile(filename)
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

// addCreatorOwnerAclToFile is required because on Windows systems, a new file doesn
func addCreatorOwnerAclToFile(filename string) error {
	// Get the DACL security descriptor from the filename
	sd, err := windows.GetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}

	// Get the DACL from the security descriptor
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	// Create a SID for the CREATOR_OWNER
	sid, err := windows.StringToSid("S-1-3-0")
	if err != nil {
		return err
	}

	// Create an access control entry (ACE) for the CREATOR_OWNER SID
	ace := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}

	newAcl := new(windows.ACL)
	newAclH := windows.Handle(unsafe.Pointer(newAcl))
	entries := []windows.EXPLICIT_ACCESS{ace}
	if err := SetEntriesInAcl(
		entries,
		windows.Handle(unsafe.Pointer(dacl)),
		&newAclH,
	); err != nil {
		return err
	}

	// Set the updated security descriptor of the file
	err = windows.SetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, newAcl, nil)
	if err != nil {
		return err
	}
	return nil
}

func SetEntriesInAcl(entries []windows.EXPLICIT_ACCESS, oldAcl windows.Handle, newAcl *windows.Handle) error {
	ret, _, _ := procSetEntriesInAclW.Call(
		uintptr(len(entries)),
		uintptr(unsafe.Pointer(&entries[0])),
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(newAcl)),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}
