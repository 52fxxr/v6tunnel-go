package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/52fxxr/v6tunnel/internal/protocol"
)

var (
	serverAddr = flag.String("server", "", "服务器地址 (IPv6:端口)")
	secret     = flag.String("s", "", "共享密钥")
)

type PortMapping struct {
	RemotePort int
	LocalHost  string
	LocalPort  int
}

type Client struct {
	serverAddr string
	secret     string
	ports      []PortMapping
	conn       net.Conn
	streams    sync.Map // map[uint16]*Stream
	running    atomic.Bool
}

type Stream struct {
	sid        uint16
	localConn  net.Conn
	client     *Client
	inbox      chan []byte
	closeChan  chan struct{}
}

func NewClient(serverAddr, secret string, ports []PortMapping) *Client {
	return &Client{
		serverAddr: serverAddr,
		secret:     secret,
		ports:      ports,
	}
}

func (c *Client) Run() error {
	c.running.Store(true)
	for c.running.Load() {
		if err := c.connect(); err != nil {
			log.Printf("连接失败: %v, 5秒后重试...", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if err := c.serve(); err != nil {
			log.Printf("连接断开: %v, 5秒后重试...", err)
		}
		c.close()
		time.Sleep(5 * time.Second)
	}
	return nil
}

func (c *Client) connect() error {
	conn, err := net.Dial("tcp", c.serverAddr)
	if err != nil {
		return err
	}
	protocol.SetTCPKeepAlive(conn)
	c.conn = conn

	// 认证
	ts := time.Now().Unix()
	token := protocol.AuthToken(c.secret, ts)
	authPayload := make([]byte, 8+32)
	binary.BigEndian.PutUint64(authPayload, uint64(ts))
	copy(authPayload[8:], token)
	if err := protocol.SendMsg(conn, protocol.MsgAuth, authPayload); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	msgType, _, err := protocol.RecvMsg(conn)
	if err != nil {
		return fmt.Errorf("recv auth response: %w", err)
	}
	if msgType != protocol.MsgAuthOK {
		return fmt.Errorf("auth rejected")
	}
	log.Println("认证成功")

	// 注册端口
	for _, pm := range c.ports {
		payload := make([]byte, 2)
		binary.BigEndian.PutUint16(payload, uint16(pm.RemotePort))
		if err := protocol.SendMsg(conn, protocol.MsgRegister, payload); err != nil {
			return fmt.Errorf("register port %d: %w", pm.RemotePort, err)
		}
		msgType, _, err := protocol.RecvMsg(conn)
		if err != nil {
			return fmt.Errorf("recv register response: %w", err)
		}
		if msgType == protocol.MsgRegisterOK {
			log.Printf("已注册端口 :%d", pm.RemotePort)
		} else {
			log.Printf("注册端口 :%d 失败", pm.RemotePort)
		}
	}

	return nil
}

func (c *Client) serve() error {
	// 启动心跳
	stopHeartbeat := make(chan struct{})
	go c.heartbeat(stopHeartbeat)
	defer close(stopHeartbeat)

	// 消息循环
	for c.running.Load() {
		msgType, payload, err := protocol.RecvMsg(c.conn)
		if err != nil {
			return err
		}

		switch msgType {
		case protocol.MsgNewStream:
			if len(payload) == 4 {
				sid := binary.BigEndian.Uint16(payload[:2])
				rport := binary.BigEndian.Uint16(payload[2:])
				go c.openStream(sid, rport)
			}

		case protocol.MsgStreamData:
			if len(payload) >= 2 {
				sid := binary.BigEndian.Uint16(payload[:2])
				data := payload[2:]
				if stream, ok := c.streams.Load(sid); ok {
					s := stream.(*Stream)
					select {
					case s.inbox <- data:
					default:
					}
				}
			}

		case protocol.MsgStreamClose:
			if len(payload) == 2 {
				sid := binary.BigEndian.Uint16(payload[:2])
				if stream, ok := c.streams.Load(sid); ok {
					s := stream.(*Stream)
					close(s.closeChan)
					c.streams.Delete(sid)
				}
			}

		case protocol.MsgPing:
			protocol.SendMsg(c.conn, protocol.MsgPong, payload)

		case protocol.MsgPong:
			// ignore
		}
	}
	return nil
}

func (c *Client) heartbeat(stop chan struct{}) {
	// 立即发第一个心跳
	protocol.SendMsg(c.conn, protocol.MsgPing, make([]byte, 8))

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := protocol.SendMsg(c.conn, protocol.MsgPing, make([]byte, 8)); err != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func (c *Client) openStream(sid uint16, rport uint16) {
	// 查找端口映射
	var mapping *PortMapping
	for _, pm := range c.ports {
		if uint16(pm.RemotePort) == rport {
			mapping = &pm
			break
		}
	}
	if mapping == nil {
		log.Printf("未知端口: %d", rport)
		c.sendStreamClose(sid)
		return
	}

	log.Printf("流 #%d -> %s:%d", sid, mapping.LocalHost, mapping.LocalPort)

	localConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", mapping.LocalHost, mapping.LocalPort))
	if err != nil {
		log.Printf("连接本地服务失败: %v", err)
		c.sendStreamClose(sid)
		return
	}
	protocol.SetTCPKeepAlive(localConn)

	stream := &Stream{
		sid:       sid,
		localConn: localConn,
		client:    c,
		inbox:     make(chan []byte, 64),
		closeChan: make(chan struct{}),
	}
	c.streams.Store(sid, stream)
	defer c.streams.Delete(sid)

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 -> 服务器
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			select {
			case <-stream.closeChan:
				return
			default:
			}
			n, err := localConn.Read(buf)
			if n > 0 {
				payload := make([]byte, 2+n)
				binary.BigEndian.PutUint16(payload, sid)
				copy(payload[2:], buf[:n])
				if err := protocol.SendMsg(c.conn, protocol.MsgStreamData, payload); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// 服务器 -> 本地
	go func() {
		defer wg.Done()
		for {
			select {
			case data := <-stream.inbox:
				if _, err := localConn.Write(data); err != nil {
					return
				}
			case <-stream.closeChan:
				return
			}
		}
	}()

	wg.Wait()
	localConn.Close()
	c.sendStreamClose(sid)
	log.Printf("流 #%d 关闭", sid)
}

func (c *Client) sendStreamClose(sid uint16) {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, sid)
	protocol.SendMsg(c.conn, protocol.MsgStreamClose, payload)
}

func (c *Client) close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) Stop() {
	c.running.Store(false)
	c.close()
}

func main() {
	flag.Parse()
	if *serverAddr == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "用法: client -server <IPv6:端口> -s <密钥>")
		os.Exit(1)
	}

	ports := []PortMapping{
		{RemotePort: 7001, LocalHost: "127.0.0.1", LocalPort: 25565},
	}

	client := NewClient(*serverAddr, *secret, ports)
	if err := client.Run(); err != nil {
		log.Fatal(err)
	}
}
