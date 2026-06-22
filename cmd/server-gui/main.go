package main

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/52fxxr/v6tunnel/internal/protocol"
	"github.com/52fxxr/v6tunnel/internal/webassets"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type PortMapping struct {
	RemotePort int    `json:"remote"`
	LocalHost  string `json:"host"`
	LocalPort  int    `json:"local"`
}

type StreamConn struct {
	sid       uint16
	inbox     chan []byte
	closeChan chan struct{}
}

type ClientConn struct {
	id          uint64
	ip          string
	conn        net.Conn
	writer      io.Writer
	ports       map[int]bool
	streams     sync.Map // map[uint16]*StreamConn
	connectedAt time.Time
	mu          sync.RWMutex
}

type Server struct {
	secret        string
	listenAddr    string
	ports         []PortMapping
	portsMu       sync.RWMutex
	clients       sync.Map // map[uint64]*ClientConn
	streamCounter atomic.Uint32
	trafficRx     atomic.Uint64
	trafficTx     atomic.Uint64
	running       atomic.Bool
	ctrlListener  net.Listener
	bizListeners  []net.Listener
	stopCh        chan struct{}
	blockedIPs    sync.Map
	logCh         chan string
	wsClients     sync.Map // map[*websocket.Conn]bool
}

type ClientInfo struct {
	ID             uint64   `json:"id"`
	IP             string   `json:"ip"`
	Ports          []string `json:"ports"`
	ConnectedSince string   `json:"connected_since"`
}

type WSMessage struct {
	Type    string        `json:"type"`
	Running bool          `json:"running,omitempty"`
	Error   string        `json:"error,omitempty"`
	Clients []ClientInfo  `json:"clients,omitempty"`
	Ports   []PortMapping `json:"ports,omitempty"`
	Rx      uint64        `json:"rx,omitempty"`
	Tx      uint64        `json:"tx,omitempty"`
	Level   string        `json:"level,omitempty"`
	Msg     string        `json:"msg,omitempty"`
}

func NewServer() *Server {
	return &Server{
		stopCh: make(chan struct{}),
		logCh:  make(chan string, 256),
	}
}

func (s *Server) broadcastWS(msg WSMessage) {
	data, _ := json.Marshal(msg)
	s.wsClients.Range(func(key, value interface{}) bool {
		ws := key.(*websocket.Conn)
		ws.WriteMessage(websocket.TextMessage, data)
		return true
	})
}

func (s *Server) addLog(level, msg string) {
	s.logCh <- msg
	s.broadcastWS(WSMessage{Type: "log", Level: level, Msg: msg})
	log.Printf("[%s] %s", level, msg)
}

func (s *Server) Start(secret string, port int, ports []PortMapping) error {
	if s.running.Load() {
		return fmt.Errorf("服务器已在运行")
	}

	s.secret = secret
	s.listenAddr = fmt.Sprintf("[::]:%d", port)
	s.ports = ports
	s.running.Store(true)

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		s.running.Store(false)
		return fmt.Errorf("监听控制端口失败: %w", err)
	}
	s.ctrlListener = listener

	for _, pm := range ports {
		go s.listenBusiness(pm)
	}

	s.addLog("ok", fmt.Sprintf("服务器已启动: control=%s, business=%v", s.listenAddr, portList(ports)))

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !s.running.Load() {
					return
				}
				continue
			}
			go s.handleControl(conn)
		}
	}()

	go s.statsLoop()
	return nil
}

func (s *Server) Stop() {
	if !s.running.Load() {
		return
	}
	s.running.Store(false)
	if s.ctrlListener != nil {
		s.ctrlListener.Close()
	}
	for _, l := range s.bizListeners {
		l.Close()
	}
	s.clients.Range(func(key, value interface{}) bool {
		c := value.(*ClientConn)
		c.conn.Close()
		return true
	})
	s.addLog("warn", "服务器已停止")
}

func (s *Server) statsLoop() {
	for s.running.Load() {
		time.Sleep(2 * time.Second)
		s.broadcastWS(WSMessage{
			Type: "status", Running: true,
			Rx: s.trafficRx.Load(), Tx: s.trafficTx.Load(),
		})
	}
}

func (s *Server) handleControl(conn net.Conn) {
	defer conn.Close()
	protocol.SetTCPKeepAlive(conn)
	peer := conn.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(peer)

	if _, blocked := s.blockedIPs.Load(clientIP); blocked {
		return
	}

	// 认证
	msgType, payload, err := protocol.RecvMsg(conn)
	if err != nil || msgType != protocol.MsgAuth || len(payload) != 8+32 {
		protocol.SendMsg(conn, protocol.MsgReject, nil)
		return
	}
	ts := int64(binary.BigEndian.Uint64(payload[:8]))
	token := payload[8:]
	expectedToken := protocol.AuthToken(s.secret, ts)
	if subtle.ConstantTimeCompare(token, expectedToken) != 1 {
		return
	}
	protocol.SendMsg(conn, protocol.MsgAuthOK, nil)

	clientID := uint64(time.Now().UnixNano())
	client := &ClientConn{
		id:          clientID,
		ip:          peer,
		conn:        conn,
		writer:      conn,
		ports:       make(map[int]bool),
		connectedAt: time.Now(),
	}
	s.clients.Store(clientID, client)
	s.addLog("info", fmt.Sprintf("客户端已连接: %s (id=%d)", peer, clientID))
	s.broadcastClients()
	defer func() {
		s.clients.Delete(clientID)
		s.addLog("warn", fmt.Sprintf("客户端断开: %s (id=%d)", peer, clientID))
		s.broadcastClients()
	}()

	// 单一读取循环：所有消息都在这里处理
	for {
		msgType, payload, err := protocol.RecvMsg(conn)
		if err != nil {
			return
		}
		switch msgType {
		case protocol.MsgRegister:
			if len(payload) == 2 {
				rport := int(binary.BigEndian.Uint16(payload))
				s.portsMu.RLock()
				_, ok := s.portsMap()[rport]
				s.portsMu.RUnlock()
				if ok {
					client.mu.Lock()
					client.ports[rport] = true
					client.mu.Unlock()
					protocol.SendMsg(conn, protocol.MsgRegisterOK, nil)
					s.broadcastClients()
				} else {
					protocol.SendMsg(conn, protocol.MsgReject, nil)
				}
			}
		case protocol.MsgPing:
			protocol.SendMsg(conn, protocol.MsgPong, payload)
		case protocol.MsgPong:
		case protocol.MsgStreamData:
			if len(payload) >= 2 {
				sid := binary.BigEndian.Uint16(payload[:2])
				data := payload[2:]
				if v, ok := client.streams.Load(sid); ok {
					sc := v.(*StreamConn)
					select {
					case sc.inbox <- data:
					default:
					}
				}
			}
		case protocol.MsgStreamClose:
			if len(payload) == 2 {
				sid := binary.BigEndian.Uint16(payload[:2])
				if v, ok := client.streams.Load(sid); ok {
					sc := v.(*StreamConn)
					close(sc.closeChan)
					client.streams.Delete(sid)
				}
			}
		}
	}
}

func (s *Server) portsMap() map[int]PortMapping {
	m := make(map[int]PortMapping)
	for _, p := range s.ports {
		m[p.RemotePort] = p
	}
	return m
}

func (s *Server) listenBusiness(pm PortMapping) {
	addr := fmt.Sprintf("[::]:%d", pm.RemotePort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.addLog("error", fmt.Sprintf("监听业务端口 :%d 失败: %v", pm.RemotePort, err))
		return
	}
	s.bizListeners = append(s.bizListeners, listener)

	for s.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go s.handleBusiness(conn, pm)
	}
}

func (s *Server) handleBusiness(extConn net.Conn, pm PortMapping) {
	defer extConn.Close()
	protocol.SetTCPKeepAlive(extConn)

	var client *ClientConn
	s.clients.Range(func(key, value interface{}) bool {
		c := value.(*ClientConn)
		c.mu.RLock()
		if c.ports[pm.RemotePort] {
			client = c
			c.mu.RUnlock()
			return false
		}
		c.mu.RUnlock()
		return true
	})
	if client == nil {
		return
	}

	sid := uint16(s.streamCounter.Add(1) & 0xFFFF)
	if sid == 0 {
		sid = 1
	}

	// 创建流数据通道
	stream := &StreamConn{
		sid:       sid,
		inbox:     make(chan []byte, 256),
		closeChan: make(chan struct{}),
	}
	client.streams.Store(sid, stream)
	defer client.streams.Delete(sid)

	// 通知客户端新建流
	notifyPayload := make([]byte, 4)
	binary.BigEndian.PutUint16(notifyPayload[:2], sid)
	binary.BigEndian.PutUint16(notifyPayload[2:], uint16(pm.RemotePort))
	if err := protocol.SendMsg(client.writer, protocol.MsgNewStream, notifyPayload); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// extConn -> client (通过控制连接，大数据包分片)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := extConn.Read(buf)
			if n > 0 {
				s.trafficRx.Add(uint64(n))
				// 分片发送，每片最多 MaxPayload 字节数据
				offset := 0
				for offset < n {
					chunk := n - offset
					if chunk > protocol.MaxPayload {
						chunk = protocol.MaxPayload
					}
					payload := make([]byte, 2+chunk)
					binary.BigEndian.PutUint16(payload, sid)
					copy(payload[2:], buf[offset:offset+chunk])
					if serr := protocol.SendMsg(client.writer, protocol.MsgStreamData, payload); serr != nil {
						return
					}
					offset += chunk
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// client -> extConn (从流数据通道读取)
	go func() {
		defer wg.Done()
		for {
			select {
			case data := <-stream.inbox:
				s.trafficTx.Add(uint64(len(data)))
				if _, werr := extConn.Write(data); werr != nil {
					return
				}
			case <-stream.closeChan:
				return
			case <-s.stopCh:
				return
			}
		}
	}()

	wg.Wait()
	protocol.SendMsg(client.writer, protocol.MsgStreamClose, binary.BigEndian.AppendUint16(nil, sid))
}

func (s *Server) broadcastClients() {
	var list []ClientInfo
	s.clients.Range(func(key, value interface{}) bool {
		c := value.(*ClientConn)
		c.mu.RLock()
		var ports []string
		for p := range c.ports {
			ports = append(ports, fmt.Sprintf(":%d", p))
		}
		if ports == nil {
			ports = []string{}
		}
		list = append(list, ClientInfo{
			ID:             c.id,
			IP:             c.ip,
			Ports:          ports,
			ConnectedSince: c.connectedAt.Format("15:04:05"),
		})
		c.mu.RUnlock()
		return true
	})
	if list == nil {
		list = []ClientInfo{}
	}
	s.broadcastWS(WSMessage{Type: "clients", Clients: list})
}

// --- HTTP Handlers ---

func (s *Server) webHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(webassets.ServerDashboard))
}

func (s *Server) wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.wsClients.Store(ws, true)
	defer func() {
		s.wsClients.Delete(ws)
		ws.Close()
	}()
	s.broadcastWS(WSMessage{Type: "status", Running: s.running.Load(), Rx: s.trafficRx.Load(), Tx: s.trafficTx.Load()})
	s.broadcastClients()
	s.portsMu.RLock()
	s.broadcastWS(WSMessage{Type: "ports", Ports: s.ports})
	s.portsMu.RUnlock()
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (s *Server) apiStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port   int           `json:"port"`
		Secret string        `json:"secret"`
		Ports  []PortMapping `json:"ports"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Ports == nil {
		req.Ports = []PortMapping{{7001, "127.0.0.1", 25565}}
	}
	err := s.Start(req.Secret, req.Port, req.Ports)
	resp := map[string]interface{}{"ok": err == nil}
	if err != nil {
		resp["error"] = err.Error()
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) apiStop(w http.ResponseWriter, r *http.Request) {
	s.Stop()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) apiAddPort(w http.ResponseWriter, r *http.Request) {
	var pm PortMapping
	json.NewDecoder(r.Body).Decode(&pm)
	s.portsMu.Lock()
	for i, p := range s.ports {
		if p.RemotePort == pm.RemotePort {
			s.ports[i] = pm
			s.portsMu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
			s.broadcastWS(WSMessage{Type: "ports", Ports: s.ports})
			return
		}
	}
	s.ports = append(s.ports, pm)
	s.portsMu.Unlock()
	if s.running.Load() {
		go s.listenBusiness(pm)
	}
	s.broadcastWS(WSMessage{Type: "ports", Ports: s.ports})
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) apiRemovePort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Remote int `json:"remote"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	s.portsMu.Lock()
	var newPorts []PortMapping
	for _, p := range s.ports {
		if p.RemotePort != req.Remote {
			newPorts = append(newPorts, p)
		}
	}
	s.ports = newPorts
	s.portsMu.Unlock()
	s.clients.Range(func(key, value interface{}) bool {
		c := value.(*ClientConn)
		c.mu.Lock()
		delete(c.ports, req.Remote)
		c.mu.Unlock()
		return true
	})
	s.broadcastClients()
	s.broadcastWS(WSMessage{Type: "ports", Ports: s.ports})
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) apiDisconnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID uint64 `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if v, ok := s.clients.Load(req.ID); ok {
		c := v.(*ClientConn)
		c.conn.Close()
		s.clients.Delete(req.ID)
		s.addLog("warn", fmt.Sprintf("管理员断开了客户端 #%d (%s)", req.ID, c.ip))
	}
	s.broadcastClients()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) apiBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	s.blockedIPs.Store(req.IP, true)
	s.clients.Range(func(key, value interface{}) bool {
		c := value.(*ClientConn)
		ip, _, _ := net.SplitHostPort(c.ip)
		if ip == req.IP {
			c.conn.Close()
			s.clients.Delete(c.id)
		}
		return true
	})
	s.addLog("warn", fmt.Sprintf("已拉黑并断开 IP: %s", req.IP))
	s.broadcastClients()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) apiGetConfig(w http.ResponseWriter, r *http.Request) {
	s.portsMu.RLock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running": s.running.Load(),
		"clients": 0,
		"ports":   s.ports,
		"rx":      s.trafficRx.Load(),
		"tx":      s.trafficTx.Load(),
	})
	s.portsMu.RUnlock()
}

func portList(ports []PortMapping) []int {
	r := make([]int, len(ports))
	for i, p := range ports {
		r[i] = p.RemotePort
	}
	return r
}

func main() {
	s := NewServer()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.webHandler)
	mux.HandleFunc("/ws", s.wsHandler)
	mux.HandleFunc("/api/start", s.apiStart)
	mux.HandleFunc("/api/stop", s.apiStop)
	mux.HandleFunc("/api/add-port", s.apiAddPort)
	mux.HandleFunc("/api/remove-port", s.apiRemovePort)
	mux.HandleFunc("/api/disconnect", s.apiDisconnect)
	mux.HandleFunc("/api/block", s.apiBlock)
	mux.HandleFunc("/api/config", s.apiGetConfig)

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  v6tunnel 服务器控制台")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("")
	fmt.Println("  启动后在浏览器中操作:")
	fmt.Println("  http://[::1]:28888")
	fmt.Println("  公网访问: http://<你的IPv6地址>:28888")
	fmt.Println("")
	fmt.Println("  按 Ctrl+C 退出")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	server := &http.Server{Addr: "[::]:28888", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	fmt.Println("\n正在关闭...")
	s.Stop()
	server.Close()
}
