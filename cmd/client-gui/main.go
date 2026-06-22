package main

import (
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/52fxxr/v6tunnel/internal/protocol"
	"github.com/gorilla/websocket"
)

//go:embed ../../web/client_ui.html
var webContent embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type PortMapping struct {
	RemotePort int    `json:"remote"`
	LocalHost  string `json:"host"`
	LocalPort  int    `json:"local"`
}

type Client struct {
	serverAddr    string
	secret        string
	ports         []PortMapping
	conn          net.Conn
	streams       sync.Map
	running       atomic.Bool
	streamCounter atomic.Uint32
	trafficRx     atomic.Uint64
	trafficTx     atomic.Uint64
	mu            sync.Mutex
	wsClients     sync.Map
	logCh         chan string
	autoReconnect bool
}

type Stream struct {
	sid       uint16
	localConn net.Conn
	inbox     chan []byte
	closeChan chan struct{}
}

type WSMessage struct {
	Type      string `json:"type"`
	Connected bool   `json:"connected,omitempty"`
	Error     string `json:"error,omitempty"`
	Level     string `json:"level,omitempty"`
	Msg       string `json:"msg,omitempty"`
	Streams   int    `json:"streams,omitempty"`
	Rx        uint64 `json:"rx,omitempty"`
	Tx        uint64 `json:"tx,omitempty"`
}

func NewClient() *Client {
	return &Client{logCh: make(chan string, 256)}
}

func (c *Client) addLog(level, msg string) {
	c.broadcastWS(WSMessage{Type: "log", Level: level, Msg: msg})
	log.Printf("[%s] %s", level, msg)
}

func (c *Client) broadcastWS(msg WSMessage) {
	data, _ := json.Marshal(msg)
	c.wsClients.Range(func(key, value interface{}) bool {
		ws := key.(*websocket.Conn)
		ws.WriteMessage(websocket.TextMessage, data)
		return true
	})
}

func (c *Client) Connect(serverAddr, secret string, ports []PortMapping, autoReconnect bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running.Load() { return fmt.Errorf("已连接") }

	c.serverAddr = serverAddr
	c.secret = secret
	c.ports = ports
	c.autoReconnect = autoReconnect
	c.running.Store(true)

	go c.runLoop()
	return nil
}

func (c *Client) runLoop() {
	for c.running.Load() {
		if err := c.connect(); err != nil {
			c.broadcastWS(WSMessage{Type: "status", Connected: false, Error: err.Error()})
			c.addLog("error", fmt.Sprintf("连接失败: %v", err))
			if !c.autoReconnect { break }
			c.addLog("info", "5秒后自动重连...")
			time.Sleep(5 * time.Second)
			continue
		}
		c.broadcastWS(WSMessage{Type: "status", Connected: true})
		if err := c.serve(); err != nil {
			c.addLog("error", fmt.Sprintf("连接断开: %v", err))
		}
		c.close()
		c.broadcastWS(WSMessage{Type: "status", Connected: false, Error: "连接断开"})
		if !c.autoReconnect { break }
		c.addLog("info", "5秒后自动重连...")
		time.Sleep(5 * time.Second)
	}
	c.running.Store(false)
}

func (c *Client) connect() error {
	conn, err := net.DialTimeout("tcp", c.serverAddr, 10*time.Second)
	if err != nil { return err }
	protocol.SetTCPKeepAlive(conn)
	c.conn = conn

	ts := time.Now().Unix()
	token := protocol.AuthToken(c.secret, ts)
	authPayload := make([]byte, 8+32)
	binary.BigEndian.PutUint64(authPayload, uint64(ts))
	copy(authPayload[8:], token)
	if err := protocol.SendMsg(conn, protocol.MsgAuth, authPayload); err != nil {
		return fmt.Errorf("认证请求失败: %w", err)
	}
	msgType, _, err := protocol.RecvMsg(conn)
	if err != nil { return fmt.Errorf("认证响应失败: %w", err) }
	if msgType != protocol.MsgAuthOK { return fmt.Errorf("认证被拒绝") }
	c.addLog("ok", "认证成功")

	for _, pm := range c.ports {
		payload := make([]byte, 2)
		binary.BigEndian.PutUint16(payload, uint16(pm.RemotePort))
		protocol.SendMsg(conn, protocol.MsgRegister, payload)
		msgType, _, _ = protocol.RecvMsg(conn)
		if msgType == protocol.MsgRegisterOK {
			c.addLog("info", fmt.Sprintf("已注册端口 :%d → %s:%d", pm.RemotePort, pm.LocalHost, pm.LocalPort))
		} else {
			c.addLog("warn", fmt.Sprintf("注册端口 :%d 失败（服务器未配置此端口）", pm.RemotePort))
		}
	}
	return nil
}

func (c *Client) serve() error {
	stopHeartbeat := make(chan struct{})
	go c.heartbeat(stopHeartbeat)
	defer close(stopHeartbeat)

	statsTick := time.NewTicker(2 * time.Second)
	defer statsTick.Stop()
	go func() {
		for range statsTick.C {
			if c.running.Load() {
				s := 0
				c.streams.Range(func(_, _ interface{}) bool { s++; return true })
				c.broadcastWS(WSMessage{
					Type: "status", Connected: true,
					Streams: s, Rx: c.trafficRx.Load(), Tx: c.trafficTx.Load(),
				})
			}
		}
	}()

	for c.running.Load() {
		msgType, payload, err := protocol.RecvMsg(c.conn)
		if err != nil { return err }

		switch msgType {
		case protocol.MsgNewStream:
			if len(payload) == 4 {
				sid := binary.BigEndian.Uint16(payload[:2])
				rport := binary.BigEndian.Uint16(payload[2:])
				go c.openStream(sid, int(rport))
			}
		case protocol.MsgStreamData:
			if len(payload) >= 2 {
				sid := binary.BigEndian.Uint16(payload[:2])
				data := payload[2:]
				if v, ok := c.streams.Load(sid); ok {
					s := v.(*Stream)
					select { case s.inbox <- data: default: }
				}
			}
		case protocol.MsgStreamClose:
			if len(payload) == 2 {
				sid := binary.BigEndian.Uint16(payload[:2])
				if v, ok := c.streams.Load(sid); ok {
					s := v.(*Stream)
					close(s.closeChan)
					c.streams.Delete(sid)
				}
			}
		case protocol.MsgPing:
			protocol.SendMsg(c.conn, protocol.MsgPong, payload)
		case protocol.MsgPong:
		}
	}
	return nil
}

func (c *Client) heartbeat(stop chan struct{}) {
	protocol.SendMsg(c.conn, protocol.MsgPing, make([]byte, 8))
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			protocol.SendMsg(c.conn, protocol.MsgPing, make([]byte, 8))
		case <-stop:
			return
		}
	}
}

func (c *Client) openStream(sid uint16, rport int) {
	var mapping *PortMapping
	for _, pm := range c.ports {
		if pm.RemotePort == rport { mapping = &pm; break }
	}
	if mapping == nil {
		c.sendStreamClose(sid)
		return
	}
	c.addLog("info", fmt.Sprintf("新建流 #%d → %s:%d", sid, mapping.LocalHost, mapping.LocalPort))

	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", mapping.LocalHost, mapping.LocalPort), 5*time.Second)
	if err != nil {
		c.addLog("error", fmt.Sprintf("流 #%d 连接本地失败: %v", sid, err))
		c.sendStreamClose(sid)
		return
	}
	protocol.SetTCPKeepAlive(localConn)

	stream := &Stream{
		sid: sid, localConn: localConn,
		inbox: make(chan []byte, 64), closeChan: make(chan struct{}),
	}
	c.streams.Store(sid, stream)
	defer c.streams.Delete(sid)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			select {
			case <-stream.closeChan: return
			default:
			}
			n, err := localConn.Read(buf)
			if n > 0 {
				c.trafficRx.Add(uint64(n))
				payload := make([]byte, 2+n)
				binary.BigEndian.PutUint16(payload, sid)
				copy(payload[2:], buf[:n])
				protocol.SendMsg(c.conn, protocol.MsgStreamData, payload)
			}
			if err != nil { return }
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case data := <-stream.inbox:
				c.trafficTx.Add(uint64(len(data)))
				localConn.Write(data)
			case <-stream.closeChan: return
			}
		}
	}()
	wg.Wait()
	localConn.Close()
	c.sendStreamClose(sid)
}

func (c *Client) sendStreamClose(sid uint16) {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, sid)
	protocol.SendMsg(c.conn, protocol.MsgStreamClose, payload)
}

func (c *Client) close() {
	if c.conn != nil { c.conn.Close(); c.conn = nil }
	c.streams.Range(func(key, value interface{}) bool {
		s := value.(*Stream)
		close(s.closeChan)
		return true
	})
	c.streams = sync.Map{}
}

func (c *Client) Disconnect() {
	c.running.Store(false)
	c.close()
	c.addLog("warn", "已手动断开连接")
	c.broadcastWS(WSMessage{Type: "status", Connected: false, Error: "已断开"})
}

func (c *Client) UpdatePorts(ports []PortMapping) {
	c.mu.Lock()
	c.ports = ports
	c.mu.Unlock()
	c.addLog("info", "端口映射已更新")
}

// --- HTTP Handlers ---

func (c *Client) webHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := webContent.ReadFile("web/client_ui.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (c *Client) wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil { return }
	c.wsClients.Store(ws, true)
	defer func() { c.wsClients.Delete(ws); ws.Close() }()
	c.broadcastWS(WSMessage{Type: "status", Connected: c.running.Load()})
	for {
		_, _, err := ws.ReadMessage()
		if err != nil { break }
	}
}

func (c *Client) apiConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server        string        `json:"server"`
		Secret        string        `json:"secret"`
		Ports         []PortMapping `json:"ports"`
		AutoReconnect bool          `json:"auto_reconnect"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	err := c.Connect(req.Server, req.Secret, req.Ports, req.AutoReconnect)
	resp := map[string]interface{}{"ok": err == nil}
	if err != nil { resp["error"] = err.Error() }
	json.NewEncoder(w).Encode(resp)
}

func (c *Client) apiDisconnect(w http.ResponseWriter, r *http.Request) {
	c.Disconnect()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (c *Client) apiUpdatePorts(w http.ResponseWriter, r *http.Request) {
	var req struct { Ports []PortMapping `json:"ports"` }
	json.NewDecoder(r.Body).Decode(&req)
	c.UpdatePorts(req.Ports)
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func main() {
	c := NewClient()

	mux := http.NewServeMux()
	mux.HandleFunc("/", c.webHandler)
	mux.HandleFunc("/ws", c.wsHandler)
	mux.HandleFunc("/api/connect", c.apiConnect)
	mux.HandleFunc("/api/disconnect", c.apiDisconnect)
	mux.HandleFunc("/api/ports", c.apiUpdatePorts)

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  v6tunnel 客户端")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("")
	fmt.Println("  请在浏览器中操作:")
	fmt.Println("  http://localhost:28889")
	fmt.Println("")
	fmt.Println("  按 Ctrl+C 退出")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	server := &http.Server{Addr: "127.0.0.1:28889", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	fmt.Println("\n正在关闭...")
	c.Disconnect()
	server.Close()
}