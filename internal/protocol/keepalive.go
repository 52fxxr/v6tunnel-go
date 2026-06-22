package protocol

import "net"

// SetTCPKeepAlive 设置 TCP 保活参数
func SetTCPKeepAlive(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tcpConn.SetNoDelay(true)
	tcpConn.SetKeepAlive(true)
}
