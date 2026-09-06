//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const installedPipeName = `\\.\pipe\LoomClient`
const maxBrokerMessage = 64 << 10

// §13.5：只授权安装时指定的用户收发；不给 FILE_CREATE_PIPE_INSTANCE，拒绝远程客户端。
func createBrokerPipe(name, operatorSID string) (windows.Handle, error) {
	sid, err := windows.StringToSid(operatorSID)
	if err != nil {
		return 0, errors.New("安装记录中的操作用户无效")
	}
	sd, err := windows.SecurityDescriptorFromString(`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;` + sid.String() + `)`)
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, maxBrokerMessage+4, maxBrokerMessage+4, 0, sa)
}

// §13.5：所有管道 I/O 都可取消；取消后等待内核释放 OVERLAPPED 和缓冲区。
func pipeOperation(ctx context.Context, pipe windows.Handle, start func(*windows.Overlapped) error) (uint32, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlap := windows.Overlapped{HEvent: event}
	err = start(&overlap)
	if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return 0, nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	var size uint32
	for {
		err = windows.GetOverlappedResult(pipe, &overlap, &size, false)
		if !errors.Is(err, windows.ERROR_IO_INCOMPLETE) {
			return size, err
		}
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(pipe, &overlap)
			_ = windows.GetOverlappedResult(pipe, &overlap, &size, true)
			return 0, ctx.Err()
		}
		_, _ = windows.WaitForSingleObject(event, 50)
	}
}

func pipeBytes(ctx context.Context, pipe windows.Handle, body []byte, write bool) error {
	for len(body) > 0 {
		n, err := pipeOperation(ctx, pipe, func(overlap *windows.Overlapped) error {
			if write {
				return windows.WriteFile(pipe, body, nil, overlap)
			}
			return windows.ReadFile(pipe, body, nil, overlap)
		})
		if err != nil {
			return err
		}
		if n == 0 || int(n) > len(body) {
			return errors.New("服务连接已关闭")
		}
		body = body[n:]
	}
	return nil
}

func readPipeMessage(ctx context.Context, pipe windows.Handle) ([]byte, error) {
	var header [4]byte
	if err := pipeBytes(ctx, pipe, header[:], false); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 || size > maxBrokerMessage {
		return nil, errors.New("服务消息长度无效")
	}
	body := make([]byte, size)
	if err := pipeBytes(ctx, pipe, body, false); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

func writePipeMessage(ctx context.Context, pipe windows.Handle, body []byte) error {
	if len(body) == 0 || len(body) > maxBrokerMessage {
		return errors.New("服务消息长度无效")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(body)))
	if err := pipeBytes(ctx, pipe, header[:], true); err != nil {
		return err
	}
	return pipeBytes(ctx, pipe, body, true)
}

func connectBrokerPipe(ctx context.Context, name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	for {
		// §13.5：只给身份识别级别，恶意管道不能借客户端令牌执行操作。
		h, err := windows.CreateFile(p, windows.FILE_GENERIC_READ|windows.FILE_WRITE_DATA|windows.FILE_WRITE_ATTRIBUTES|windows.FILE_WRITE_EA, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return h, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return 0, fmt.Errorf("无法连接 Loom 服务；请先安装 MSI，并使用安装时的 Windows 用户打开客户端：%w", err)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func verifyBrokerServer(pipe windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil {
		return err
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	service := &mgr.Service{Name: serviceName, Handle: h}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if pid == 0 || status.State != svc.Running || status.ProcessId != pid {
		return fmt.Errorf("拒绝非 SCM 注册服务的本机连接")
	}
	return nil
}
