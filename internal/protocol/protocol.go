// Package protocol 定义 v6tunnel 的通信协议
package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	MsgAuth        = 0x01
	MsgAuthOK      = 0x02
	MsgRegister    = 0x03
	MsgRegisterOK  = 0x04
	MsgReject      = 0x05
	MsgPing        = 0x06
	MsgPong        = 0x07
	MsgNewStream   = 0x10
	MsgStreamData  = 0x11
	MsgStreamClose = 0x12
)

var msgNames = map[byte]string{
	MsgAuth:        "AUTH",
	MsgAuthOK:      "AUTH_OK",
	MsgRegister:    "REGISTER",
	MsgRegisterOK:  "REGISTER_OK",
	MsgReject:      "REJECT",
	MsgPing:        "PING",
	MsgPong:        "PONG",
	MsgNewStream:   "NEW_STREAM",
	MsgStreamData:  "STREAM_DATA",
	MsgStreamClose: "STREAM_CLOSE",
}

func MsgName(t byte) string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", t)
}

// AuthToken 生成认证令牌
func AuthToken(secret string, ts int64) []byte {
	h := sha256.New()
	h.Write([]byte(secret))
	binary.Write(h, binary.BigEndian, ts)
	return h.Sum(nil)
}

// SendMsg 发送一条协议消息
func SendMsg(w io.Writer, msgType byte, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	header := make([]byte, 3)
	header[0] = msgType
	binary.BigEndian.PutUint16(header[1:], uint16(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// RecvMsg 接收一条协议消息
func RecvMsg(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	length := binary.BigEndian.Uint16(header[1:])
	if length == 0 {
		return msgType, nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

// SetTCPKeepAlive 设置 TCP 保活参数
func SetTCPKeepAlive(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tcpConn.SetNoDelay(true)
	tcpConn.SetKeepAlive(true)
	// 尝试设置更激进的 keepalive 参数（Linux）
	if raw, err := tcpConn.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			setKeepAliveParams(int(fd))
		})
	}
}
