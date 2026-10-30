//go:build unix

package jail

import "golang.org/x/sys/unix"

// diskFree returns the bytes available to unprivileged users on the
// filesystem holding path.
func diskFree(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// nonBlock opens FIFOs without waiting for the other end. Regular files
// ignore it.
const nonBlock = unix.O_NONBLOCK
