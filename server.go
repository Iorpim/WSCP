// +build ignore

package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"./transfer"
	"./transfer/packet"
	"github.com/gorilla/websocket"
)

func checkHash(fd *os.File, checksum string) (bool, bool) {
	offset, err := fd.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Fatalln("Failed to get current file offset while calculating file hash\nError: ", err)
	}
	_, err = fd.Seek(0, io.SeekStart)
	if err != nil {
		log.Fatalln("Failed to seek file start while calculating file hash\nError: ", err)
	}
	hash := transfer.HashFile(fd)
	_, err = fd.Seek(offset, io.SeekStart)
	if err != nil {
		log.Println("Failed to seek file offset while calculating file hash\nError: ", err)
	}
	//debugln(fmt.Sprintf("Calculated file hash: %s", hash), 3)

	return hash == checksum, err != nil
}

func transferData(h http.ResponseWriter, r *http.Request) {
	//log.Println("Connection received from %s", addr)
	upgrader := websocket.Upgrader{}
	c, err := upgrader.Upgrade(h, r, nil)
	if err != nil {
		log.Println("Failed to upgrade connection\nError: ", err)
		return
	}
	defer c.Close()
	//debugln("Upgraded connection", 2)

	mt, msg, err := c.ReadMessage()
	if err != nil {
		log.Panicln("Failed to read message\nError: ", err)
		return
	}
	//debugln(fmt.Sprintf("Read message %u", msg), 5)
	p := packet.New(msg)
	b, _ := p.ParseContent()
	hs := b.(packet.HandshakeMessage)
	t := transfer.Handshake(&hs)

	p.Type = packet.Handshake
	p.AddContent(packet.HandshakeMessage{
		Key: t.RSA.GenerateSymmetricKey(),
	})
	c.WriteMessage(mt, t.PubKey.PubEncrypt(p.Encode()))

	mt, msg, err = c.ReadMessage()
	p = packet.New(t.Decrypt(msg))
	b, _ = p.ParseContent()
	init := b.(packet.InitMessage)
	t.Init(&init, "received")
	defer t.Fd.Close()

	p.Type = packet.Ack
	p.AddContent(packet.AckMessage{})
	c.WriteMessage(mt, t.Encrypt(p.Encode()))
	log.Println("Handshake complete")
	log.Print(t)
	cache := 0

	for {
		mt, msg, err := c.ReadMessage()
		if err != nil {
			if e, c := err.(*websocket.CloseError); c && e.Code == 1000 {
				log.Println("Transfer session complete")
				break
			}
			log.Println("Error: ", err)
			break
		}
		p = packet.New(t.Decrypt(msg))
		b, _ = p.ParseContent()
		content := b.(packet.ContentMessage)
		/*hash := sha256.New() // Not really necessary, the crypto layer already does integrity checking
		if base64.StdEncoding.EncodeToString(hash.Sum(content.Content)) != content.Checksum {
			p := packet.Packet{
				Type: packet.Replay,
			}
			p.AddContent(packet.ReplayMessage{})
			c.WriteMessage(mt, t.Encrypt(p.Encode()))
			i--
			continue
		}*/
		n, err := t.Fd.Write(content.Content)
		if err != nil {
			log.Fatalln("Failed to write to file\nError: ", err)
		}
		// If cache > 75Mb, commit changes to disk
		if cache += n; cache > 78643200 {
			t.Fd.Sync()
			cache = 0
		}

		p := packet.Packet{
			Type: packet.Ack,
		}
		p.AddContent(packet.AckMessage{})
		c.WriteMessage(mt, t.Encrypt(p.Encode()))
	}
	log.Println("Finished writing to file")
	if matching, _ := checkHash(t.Fd, t.Checksum); matching {
		log.Println("Matching file hash found, file integrity confirmed")
	} else {
		log.Println("Failed to match file hash, new transfer required")
	}
}

func main() {
	addr := "127.0.0.1:8989"
	//http.HandleFunc("/", serve)
	http.HandleFunc("/api", transferData)
	http.ListenAndServe(addr, nil)
}
