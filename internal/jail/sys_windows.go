package jail

import "golang.org/x/sys/windows"

// diskFree returns the bytes available to this user on the volume holding
// path.
func diskFree(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var free uint64
	err = windows.GetDiskFreeSpaceEx(p, &free, nil, nil)
	return free, err
}

// nonBlock is for FIFOs, which Windows doesn't have.
const nonBlock = 0
