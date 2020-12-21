package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"./transfer"
	"./transfer/packet"

	"github.com/gorilla/websocket"
)

var verbose int
var proxy string
var stride int

var ascii bool

func parseArgs() (string, string) {
	flag.StringVar(&proxy, "p", "", "Enable proxy passthrough.\nFormat: {scheme}://[user[:password]@]{address}[:port]")
	flag.IntVar(&verbose, "v", 0, "Enables verbose output.")
	flag.IntVar(&stride, "s", 256*1024, "Defines the packet size")
	flag.BoolVar(&ascii, "a", false, "Makes progress bar output ASCII only")
	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Println("Missing arguments!")
		log.Fatalf("Usage: %s [-h] [-p {scheme}://[user[:password]@]{address}[:port]] [-v {n}] [-s {n}] [-a] {address} {file}\n", filepath.Base(os.Args[0]))
	}

	//fmt.Println(flag.Args())
	//fmt.Println(proxy, verbose)
	return flag.Arg(0), flag.Arg(1)
}

func debugln(s string, i int) {
	if verbose >= i {
		fmt.Println(s)
	}
}

func parseURL(addr string) *url.URL {
	u, err := url.Parse(addr)
	if err != nil {
		debugln(fmt.Sprintf(" - Address: %s", addr), 2)
		log.Fatal("URL PARSING ERROR: ", err)
	}
	//{scheme: "ws", Host: addr, Path: "/"}
	if u.Scheme == "" {
		u.Scheme = "ws"
	}

	return u
}

func connect(u *url.URL, p *url.URL) *websocket.Conn {
	var dialer *websocket.Dialer
	var h http.Header
	if u.User != nil {
		credentials, _ := url.PathUnescape(u.User.String())
		h = http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))}}
		u.User = nil
	} else {
		h = nil
	}

	debugln(fmt.Sprintf(" - Connecting to %s", u.String()), 1)

	if p != nil {
		dialer = &websocket.Dialer{
			Proxy: http.ProxyURL(p),
		}
	} else {
		dialer = websocket.DefaultDialer
	}

	c, r, err := dialer.Dial(u.String(), h)
	if err != nil {
		debugln(string(r.StatusCode), 4)
		body, _ := ioutil.ReadAll(r.Body)
		debugln(string(body), 4)
		// TODO: Play dial up sound when connecting
		log.Fatal("Failed to dial address!\nError: ", err)
	}
	return c
}

func handshakeConnection(c *websocket.Conn, t *transfer.Transfer) {
	handshake := packet.HandshakeMessage{PubKey: t.RSA.Bytes()}

	p := packet.Packet{Type: packet.Handshake}
	p.AddContent(handshake)
	debugln(" - Sending handshake message", 1)
	c.WriteMessage(websocket.BinaryMessage, p.Encode())

	_, msg, _ := c.ReadMessage()
	res := packet.New(t.Decrypt(msg))
	b, _ := res.ParseContent()
	debugln(" - Received response", 3)
	h := b.(packet.HandshakeMessage)
	debugln(" - Received valid handshake", 2)
	t.RSA.SetSymmetricKey(h.Key)
	debugln(" - Received valid AES key", 2)
	debugln(" - Initiating packet processing", 3)
	t.InitPackets()

	init := packet.InitMessage{Size: t.Size, Filename: t.Filename, Checksum: t.Checksum, PacketCount: t.PacketCount, Index: t.Index}
	p.Type = packet.Init
	p.AddContent(init)
	debugln(" - Sending init message", 2)
	c.WriteMessage(websocket.BinaryMessage, t.Encrypt(p.Encode()))

	_, msg, _ = c.ReadMessage()
	debugln(" - Received response", 3)
	res = packet.New(t.Decrypt(msg))
	debugln(" - Received valid encrypted response", 2)
	if res.Type != packet.Ack {
		log.Panicln("Handshake failed\nReceived type: ", res.Type)
	}
	debugln(" - Received ACK", 3)
	debugln(" - Handshake completed", 2)
}

func sendFile(c *websocket.Conn, t *transfer.Transfer) {
	fmt.Println("")
	for pkt := range t.Packets {
		debugln(fmt.Sprintf(" - Sending packet n° %d", t.Index), 3)
		t.Replay = pkt
		c.WriteMessage(websocket.BinaryMessage, pkt)
		t.PrintProgress(50, ascii)

		_, msg, _ := c.ReadMessage()
		res := packet.New(t.Decrypt(msg))
		for res.Type == packet.Replay {
			debugln(" - Replay request received", 1)
			c.WriteMessage(websocket.BinaryMessage, t.Replay)

			_, msg, _ = c.ReadMessage()
			res = packet.New(t.Decrypt(msg))
		}
		if res.Type != packet.Ack {
			log.Fatalln("Invalid message type received\nType: ", res.Type)
		}
		debugln(" - Received ACK", 4)
	}
	fmt.Println("")
}

func removeCreds(u *url.URL) string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

func main() {
	fmt.Println("     ..:: WScp ::..     ")
	addr, filename := parseArgs()
	u := parseURL(addr)
	fmt.Printf("[+] Sending: %s\n", filename)
	var p *url.URL
	if proxy != "" {
		p = parseURL(proxy)
		fmt.Printf("[+] Proxy: %s\n", removeCreds(p))
	} else {
		p = nil
	}
	fmt.Printf("[+] Destination: %s\n\n", removeCreds(u))
	c := connect(u, p)
	defer c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

	t := transfer.New(filename, 1024)
	t.UpdateStride(stride)
	handshakeConnection(c, t)
	sendFile(c, t)

	//done := make(chan struct{})
}
