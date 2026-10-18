package control

import (
	"net"
	"sync"
	"time"
)

// Each address is an independent execution input. Losing a WG address cannot
// stop the authority, local admin listener, or another usable private address.
func (channel *PrivateChannel) startPrivateListeners(listen func(string, string) (net.Listener, error), retry time.Duration) {
	for _, address := range channel.config.Listen {
		listener, _ := listen("tcp", address)
		if listener != nil {
			channel.transportM.Lock()
			channel.listeners[address] = listener
			channel.transportM.Unlock()
		}
		channel.workers.Add(1)
		go channel.maintainPrivateListener(address, listener, listen, retry)
	}
}

func (channel *PrivateChannel) maintainPrivateListener(address string, listener net.Listener, listen func(string, string) (net.Listener, error), retry time.Duration) {
	defer channel.workers.Done()
	for {
		if listener != nil {
			channel.accept(listener)
			_ = listener.Close()
			channel.transportM.Lock()
			delete(channel.listeners, address)
			channel.transportM.Unlock()
		}
		timer := time.NewTimer(retry)
		select {
		case <-channel.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		listener, _ = listen("tcp", address)
		if listener == nil {
			continue
		}
		channel.transportM.Lock()
		select {
		case <-channel.done:
			channel.transportM.Unlock()
			_ = listener.Close()
			return
		default:
			channel.listeners[address] = listener
			channel.transportM.Unlock()
		}
	}
}

type privateConnection struct {
	net.Conn
	channel *PrivateChannel
	once    sync.Once
}

func (connection *privateConnection) Close() error {
	var err error
	connection.once.Do(func() {
		err = connection.Conn.Close()
		connection.channel.transportM.Lock()
		delete(connection.channel.connections, connection)
		connection.channel.transportM.Unlock()
	})
	return err
}

func (connection *privateConnection) CloseWrite() error {
	if connection, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return connection.CloseWrite()
	}
	return nil
}

func (channel *PrivateChannel) trackPrivateConnection(connection net.Conn) net.Conn {
	channel.transportM.Lock()
	defer channel.transportM.Unlock()
	select {
	case <-channel.done:
		_ = connection.Close()
		return nil
	default:
	}
	if channel.connections == nil {
		channel.connections = map[*privateConnection]struct{}{}
	}
	tracked := &privateConnection{Conn: connection, channel: channel}
	channel.connections[tracked] = struct{}{}
	return tracked
}
