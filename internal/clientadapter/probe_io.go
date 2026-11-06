package clientadapter

import "net"

// The request owner joins complete socket operations, including measurement
// quota refunds. Its shared closing check also rejects late Transport I/O.
type probeOwnedConn struct {
	net.Conn
	begin func() bool
	done  func()
}

func (connection *probeOwnedConn) Read(body []byte) (int, error) {
	if !connection.begin() {
		return 0, net.ErrClosed
	}
	defer connection.done()
	return connection.Conn.Read(body)
}

func (connection *probeOwnedConn) Write(body []byte) (int, error) {
	if !connection.begin() {
		return 0, net.ErrClosed
	}
	defer connection.done()
	return connection.Conn.Write(body)
}
