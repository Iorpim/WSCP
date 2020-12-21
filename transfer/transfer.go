package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path"
	"strings"

	"./packet"
	"./rsa"
)

/*const (
	init
)*/

// Transfer - Transfer
type Transfer struct {
	Size        int
	Filename    string
	Checksum    string
	Packets     chan []byte
	PacketCount int
	Index       int
	RSA         *rsa.RSA
	PubKey      *rsa.RSA
	Replay      []byte
	Fd          *os.File
	stride      int
}

// New - New
func New(filename string, stride int) *Transfer {
	fd, err := os.Open(filename)
	if err != nil {
		log.Fatal("Failed to open file\nError: ", err)
	}

	stat, _ := fd.Stat()
	ret := Transfer{
		Size:     int(stat.Size()),
		Filename: filename,
		Checksum: HashFile(fd),
		Index:    0,
		RSA:      rsa.GenerateKeys(),
		Fd:       fd,
		stride:   stride,
	}
	ret.PacketCount = ret.Size/ret.stride + 1

	return &ret
}

// Handshake - Instantiate transfer from handshake message
func Handshake(pubkey *packet.HandshakeMessage) *Transfer {
	return &Transfer{
		RSA:    rsa.GenerateKeys(),
		PubKey: rsa.New(pubkey.PubKey),
	}
}

// Init - Iniate a transfer instance from a init message
func (t *Transfer) Init(msg *packet.InitMessage, outputDir string) {
	t.Size = msg.Size
	t.Filename = msg.Filename
	t.Checksum = msg.Checksum
	t.PacketCount = msg.PacketCount
	t.Index = msg.Index
	fd, err := os.Create(outputDir + "/" + path.Base(t.Filename))
	if err != nil {
		log.Fatalln("Failed to create file\nError: ", err)
	}
	t.Fd = fd
}

// InitPackets - Init packets
func (t *Transfer) InitPackets() {
	t.Packets = t.splitFile()
}

// Encrypt - Encrypt
func (t *Transfer) Encrypt(b []byte) []byte {
	return t.RSA.Encrypt(b)
}

// Decrypt - Decrypt
func (t *Transfer) Decrypt(b []byte) []byte {
	return t.RSA.Decrypt(b)
}

// UpdateStride - Update stride
func (t *Transfer) UpdateStride(i int) {
	t.stride = i
	t.PacketCount = t.Size/t.stride + 1
}

// Handle - Handles WebSockets messages
//func (t *Transfer) Handle() {
//
//}

func prettyBytes(i int) string {
	units := []string{"", "K", "M", "G", "T", "P"}
	index := math.Floor(math.Log(float64(i)) / math.Log(1024))
	size := float64(i) / math.Pow(1024, index)
	return fmt.Sprintf("%.02f %sB", size, units[int(index)])
}

// PrintProgress - Print progress bar
func (t *Transfer) PrintProgress(l int, ascii bool) {
	current := t.Index * t.stride
	progress := int(math.Round(float64(current) / float64(t.Size) * float64(l)))
	var chars []string
	if !ascii {
		chars = []string{"▮", "▯"}
	} else {
		chars = []string{"#", " "}
	}
	fmt.Printf("  %s - %d pkt |%s%s| %d pkt - %s                          \r", prettyBytes(current), t.Index, strings.Repeat(chars[0], progress), strings.Repeat(chars[1], l-progress), t.PacketCount, prettyBytes(t.Size))
}

// HashFile - Hash file
func HashFile(fd *os.File) string {
	ret := sha256.New()

	if _, err := io.Copy(ret, fd); err != nil {
		log.Fatal("Failed to calculate file checksum\nError: ", err)
	}

	fd.Seek(0, io.SeekStart)
	return hex.EncodeToString(ret.Sum(nil))
}

func (t *Transfer) splitFile() chan []byte {
	ret := make(chan []byte)
	go func(t *Transfer, c chan []byte) {
		defer t.Fd.Close()
		defer close(c)
		b := make([]byte, t.stride)
		for {
			n, err := t.Fd.Read(b)
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Fatal("Failed to read file\nError: ", err)
			}
			b = b[:n]
			hash := sha256.New()
			msg := packet.ContentMessage{Content: b, Checksum: base64.StdEncoding.EncodeToString(hash.Sum(b))}
			var buf bytes.Buffer
			encoder := gob.NewEncoder(&buf)
			encoder.Encode(msg)
			t.Index++
			c <- t.Encrypt((&packet.Packet{Type: packet.Content, Content: buf.Bytes()}).Encode())
		}
		//c <- ""
	}(t, ret)

	return ret
}
