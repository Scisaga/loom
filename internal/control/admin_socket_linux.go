package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func adminEntryOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// The empty lock only owns this local listener. It is never an authority value
// and must not be unlinked while a process can hold its kernel lock.
func listenControlAdmin(ctx context.Context, path string) (net.Listener, error) {
	if !absoluteControlPath(path) {
		return nil, errors.New("admin socket requires a canonical absolute path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 || !adminEntryOwned(parent) {
		return nil, errors.New("admin socket parent must be private and owned by the current user")
	}
	lockPath := path + ".listen.lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if !controlPrivateRegular(info) || !adminEntryOwned(info) || info.Size() != 0 {
			return nil, errors.New("admin socket lock is not an owned empty protected file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	acquire, cancel := context.WithTimeout(ctx, time.Second)
	lock, err := lockProtectedControlPath(acquire, lockPath)
	cancel()
	if err != nil {
		return nil, err
	}
	keepLock := false
	defer func() {
		if !keepLock {
			lock.Close()
		}
	}()
	info, err := lock.Stat()
	if err != nil || !adminEntryOwned(info) || info.Size() != 0 {
		return nil, errors.New("admin socket lock changed while opening")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entry, err := os.Lstat(path)
	if err == nil {
		if entry.Mode()&os.ModeSocket == 0 || entry.Mode().Perm()&0o077 != 0 || !adminEntryOwned(entry) {
			return nil, errors.New("existing admin entry is not an owned protected socket")
		}
		connection, err := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "unix", path)
		if err == nil {
			connection.Close()
			return nil, errors.New("admin socket still has a listener")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, errors.New("admin socket has not been proven inactive")
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(entry, current) || entry.Mode() != current.Mode() || !adminEntryOwned(current) {
			return nil, errors.New("admin socket changed while checking inactivity")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	entry, err = os.Lstat(path)
	if err != nil {
		listener.Close()
		return nil, err
	}
	owned := &controlAdminListener{UnixListener: listener, path: path, entry: entry, lock: lock}
	keepLock = true
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(err, owned.Close())
	}
	return owned, nil
}

type controlAdminListener struct {
	*net.UnixListener
	path  string
	entry os.FileInfo
	lock  *os.File
	once  sync.Once
	err   error
}

func (listener *controlAdminListener) Close() error {
	listener.once.Do(func() {
		listener.err = listener.UnixListener.Close()
		current, err := os.Lstat(listener.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			listener.err = errors.Join(listener.err, err)
		case !os.SameFile(listener.entry, current) || current.Mode()&os.ModeSocket == 0 || !adminEntryOwned(current):
			listener.err = errors.Join(listener.err, errors.New("admin socket was replaced; preserving the unowned entry"))
		default:
			listener.err = errors.Join(listener.err, os.Remove(listener.path))
		}
		listener.err = errors.Join(listener.err, listener.lock.Close())
	})
	return listener.err
}
