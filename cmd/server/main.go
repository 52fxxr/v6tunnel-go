package main

import (
	"crypto/subtle"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/52fxxr/v6tunnel/internal/protocol"
)

var (
	secret     = flag.String("s", "", "共享密钥")
	listenAddr = flag.String("l", "[::]:7000", "监听地址")
)

type PortMapping struct {
	RemotePort int
	LocalHost  string
	LocalPort  int
}

type Server struct {
	secret        string
	listenAddr    string
	ports         map[int]*PortMapping
	clients       sync.Map // map[uint64]*ClientConn
	streamCounter atomic.Uint32
	trafficRx     atomic.Uint64
	trafficTx     atomic.Uint64
}

type ClientConn struct {
	id     uint64
	conn   net.Conn
	reader io.Reader
	writer io.Writer
	ports  map[int]bool
	mu     sync.RWMutex
}

func NewServer(secret, listenAddr string, ports []PortMapping) *Server {
	s := &Server{
		secret:     secret,
		listenAddr: listenAddr,
		ports:      make(map[int]*PortMapping),
	}
	for _, p := range ports {
		s.ports[p.RemotePort] = &p
	}
	return s
}

func (s *Server) Run() error {
	// 启动业务端口监听
	for rport, pm := range s.ports {
		go s.listenBusiness(rport, pm)
	}

	// 启动控制端口监听
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen control: %w", err)
	}
	defer listener.Close()
	log.Printf("server listening: control=%s, business=%v", s.listenAddr, getPortKeys(s.ports))

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.handleControl(conn)
	}
}

func (s *Server) handleControl(conn net.Conn) {
	defer conn.Close()
	protocol.SetTCPKeepAlive(conn)

	peer := conn.RemoteAddr().String()
	log.Printf("control: new connection from %s", peer)

	// 认证
	msgType, payload, err := protocol.RecvMsg(conn)
	if err != nil || msgType != protocol.MsgAuth || len(payload) != 8+32 {
		protocol.SendMsg(conn, protocol.MsgReject, nil)
		return
	}

	ts := int64(binary.BigEndian.Uint64(payload[:8]))
	token := payload[8:]

	// 校验密钥（不校验时间戳，兼容时钟偏差）
	expectedToken := protocol.AuthToken(s.secret, ts)
	if subtle.ConstantTimeCompare(token, expectedToken) != 1 {
		log.Printf("control: auth failed from %s", peer)
		return
	}

	if err := protocol.SendMsg(conn, protocol.MsgAuthOK, nil); err != nil {
		return
	}
	log.Printf("control: auth ok from %s", peer)

	// 注册客户端
	clientID := s.streamCounter.Add(1)
	client := &ClientConn{
		id:     uint64(clientID),
		conn:   conn,
		reader: conn,
		writer: conn,
		ports:  make(map[int]bool),
	}
	s.clients.Store(client.id, client)
	defer s.clients.Delete(client.id)

	// 消息循环
	for {
		msgType, payload, err := protocol.RecvMsg(conn)
		if err != nil {
			log.Printf("control: connection lost from %s: %v", peer, err)
			return
		}

		switch msgType {
		case protocol.MsgRegister:
			if len(payload) == 2 {
				rport := int(binary.BigEndian.Uint16(payload))
				if _, ok := s.ports[rport]; ok {
					client.mu.Lock()
					client.ports[rport] = true
					client.mu.Unlock()
					protocol.SendMsg(conn, protocol.MsgRegisterOK, nil)
					log.Printf("control: %s registered :%d", peer, rport)
				} else {
					protocol.SendMsg(conn, protocol.MsgReject, nil)
				}
			}

		case protocol.MsgPing:
			protocol.SendMsg(conn, protocol.MsgPong, payload)

		case protocol.MsgPong:
			// ignore

		case protocol.MsgStreamClose:
			// 流关闭通知，由业务端处理
		}
	}
}

func (s *Server) listenBusiness(rport int, pm *PortMapping) {
	addr := fmt.Sprintf("[::]:%d", rport)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("business: failed to listen :%d: %v", rport, err)
		return
	}
	defer listener.Close()
	log.Printf("business :%d -> %s:%d", rport, pm.LocalHost, pm.LocalPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("business accept error: %v", err)
			continue
		}
		go s.handleBusiness(conn, rport, pm)
	}
}

func (s *Server) handleBusiness(extConn net.Conn, rport int, pm *PortMapping) {
	defer extConn.Close()
	protocol.SetTCPKeepAlive(extConn)

	peer := extConn.RemoteAddr().String()

	// 找一个注册了该端口的客户端
	var client *ClientConn
	s.clients.Range(func(key, value interface{}) bool {
		c := value.(*ClientConn)
		c.mu.RLock()
		if c.ports[rport] {
			client = c
			c.mu.RUnlock()
			return false
		}
		c.mu.RUnlock()
		return true
	})

	if client == nil {
		log.Printf("business: %s -> :%d (no client registered) closing", peer, rport)
		return
	}

	// 分配 stream ID
	sid := uint16(s.streamCounter.Add(1) & 0xFFFF)
	if sid == 0 {
		sid = 1
	}

	log.Printf("business: %s -> :%d stream #%d", peer, rport, sid)

	// 通知客户端新流
	notifyPayload := make([]byte, 4)
	binary.BigEndian.PutUint16(notifyPayload[:2], sid)
	binary.BigEndian.PutUint16(notifyPayload[2:], uint16(rport))
	if err := protocol.SendMsg(client.writer, protocol.MsgNewStream, notifyPayload); err != nil {
		log.Printf("business: notify client failed: %v", err)
		return
	}

	// 连接本地服务
	localConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pm.LocalHost, pm.LocalPort))
	if err != nil {
		log.Printf("business: connect local %s:%d failed: %v", pm.LocalHost, pm.LocalPort, err)
		protocol.SendMsg(client.writer, protocol.MsgStreamClose, binary.BigEndian.AppendUint16(nil, sid))
		return
	}
	defer localConn.Close()
	protocol.SetTCPKeepAlive(localConn)

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// ext -> local (通过控制通道)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := extConn.Read(buf)
			if n > 0 {
				s.trafficRx.Add(uint64(n))
				payload := make([]byte, 2+n)
				binary.BigEndian.PutUint16(payload, sid)
				copy(payload[2:], buf[:n])
				if err := protocol.SendMsg(client.writer, protocol.MsgStreamData, payload); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// local -> ext
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				s.trafficTx.Add(uint64(n))
				if _, err := extConn.Write(buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	protocol.SendMsg(client.writer, protocol.MsgStreamClose, binary.BigEndian.AppendUint16(nil, sid))
	log.Printf("business: stream #%d closed", sid)
}

func getPortKeys(m map[int]*PortMapping) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func main() {
	flag.Parse()
	if *secret == "" {
		fmt.Println("v6tunnel 服务器端")
		fmt.Println("用法: v6tunnel-server.exe -s <共享密钥> [-l [::]:7000]")
		fmt.Println("")
		fmt.Println("示例:")
		fmt.Println("  v6tunnel-server.exe -s mysecret")
		fmt.Println("  v6tunnel-server.exe -s mysecret -l [::]:7000")
		fmt.Println("")
		fmt.Println("按回车键退出...")
		fmt.Scanln()
		os.Exit(1)
	}

	ports := []PortMapping{
		{RemotePort: 7001, LocalHost: "127.0.0.1", LocalPort: 25565},
	}

	server := NewServer(*secret, *listenAddr, ports)
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
