//go:build windows

package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// keyRead is KEY_READ: STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY.
const keyRead = 0x20019

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegQueryInfoKe = advapi32.NewProc("RegQueryInfoKeyW")
)

type registryWin struct{}

func newRegistry() Registry { return registryWin{} }

func hiveHandle(hive string) (syscall.Handle, error) {
	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return syscall.HKEY_LOCAL_MACHINE, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return syscall.HKEY_CURRENT_USER, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return syscall.HKEY_CLASSES_ROOT, nil
	case "HKU", "HKEY_USERS":
		return syscall.HKEY_USERS, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return syscall.HKEY_CURRENT_CONFIG, nil
	}
	return 0, fmt.Errorf("unknown hive %q", hive)
}

func openKey(hive, path string) (syscall.Handle, error) {
	root, err := hiveHandle(hive)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(root, syscall.StringToUTF16Ptr(path), 0, keyRead, &h); err != nil {
		return 0, err
	}
	return h, nil
}

func (registryWin) GetString(hive, path, name string) (string, bool, error) {
	h, err := openKey(hive, path)
	if err != nil {
		if errors.Is(err, syscall.Errno(2)) { // ERROR_FILE_NOT_FOUND: key absent
			return "", false, nil
		}
		return "", false, err
	}
	defer syscall.RegCloseKey(h)

	var typ, size uint32
	if err := syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(name), nil, &typ, nil, &size); err != nil {
		if errors.Is(err, syscall.Errno(2)) { // value absent
			return "", false, nil
		}
		return "", false, err
	}
	if size == 0 {
		return "", true, nil
	}
	buf := make([]byte, size)
	if err := syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(name), nil, &typ, &buf[0], &size); err != nil {
		return "", false, err
	}
	return decodeValue(typ, buf)
}

func decodeValue(typ uint32, buf []byte) (string, bool, error) {
	switch typ {
	case syscall.REG_SZ, syscall.REG_EXPAND_SZ:
		return utf16BytesToString(buf), true, nil
	case syscall.REG_DWORD:
		if len(buf) < 4 {
			return "", false, fmt.Errorf("short REG_DWORD: %d bytes", len(buf))
		}
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf[:4])), 10), true, nil
	case syscall.REG_QWORD:
		if len(buf) < 8 {
			return "", false, fmt.Errorf("short REG_QWORD: %d bytes", len(buf))
		}
		return strconv.FormatUint(binary.LittleEndian.Uint64(buf[:8]), 10), true, nil
	case syscall.REG_BINARY:
		return fmt.Sprintf("%#x", buf), true, nil
	case syscall.REG_MULTI_SZ:
		parts := strings.Split(utf16BytesToString(buf), "\x00")
		return strings.Join(parts, ", "), true, nil
	}
	return "", false, fmt.Errorf("unhandled registry type %d", typ)
}

// KeyLastWrite reads ftLastWriteTime via RegQueryInfoKeyW. This is the single
// most valuable primitive in whodunit: it works after the fact, with no
// pre-existing snapshot and no audit policy.
func (registryWin) KeyLastWrite(hive, path string) (time.Time, error) {
	h, err := openKey(hive, path)
	if err != nil {
		return time.Time{}, err
	}
	defer syscall.RegCloseKey(h)

	var ft syscall.Filetime
	ret, _, err := procRegQueryInfoKe.Call(
		uintptr(h),
		0, 0, // lpClass, lpcchClass
		0,    // lpReserved
		0, 0, // lpcSubKeys, lpcbMaxSubKeyLen
		0,    // lpcbMaxClassLen
		0, 0, // lpcValues, lpcbMaxValueNameLen
		0, // lpcbMaxValueLen
		0, // lpcbSecurityDescriptor
		uintptr(unsafe.Pointer(&ft)),
	)
	if ret != 0 {
		if err != nil && err != syscall.Errno(0) {
			return time.Time{}, err
		}
		return time.Time{}, syscall.Errno(ret)
	}
	return filetimeToTime(ft), nil
}

func (registryWin) KeyExists(hive, path string) (bool, error) {
	h, err := openKey(hive, path)
	if err != nil {
		if errors.Is(err, syscall.Errno(2)) {
			return false, nil
		}
		return false, err
	}
	syscall.RegCloseKey(h)
	return true, nil
}

func filetimeToTime(ft syscall.Filetime) time.Time {
	n := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
	if n == 0 {
		return time.Time{}
	}
	// FILETIME is 100ns ticks since 1601-01-01 UTC.
	return time.Unix(0, (n-116444736000000000)*100).UTC()
}

func utf16BytesToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return syscall.UTF16ToString(u)
}
