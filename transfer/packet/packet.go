package packet

import (
	"bytes"
	"encoding/gob"
	"errors"
	"log"
)

const (
	// Handshake - HandshakeMessage
	Handshake = iota
	// Init - InitMessage
	Init = iota
	// Ack - AckMessage
	Ack = iota
	// Sync - SyncMessage
	Sync = iota
	// Replay - ReplayMessage
	Replay = iota
	// Content - ContentMessage
	Content = iota
)

// Packet - Packet
type Packet struct {
	Type    byte
	Content []byte
}

// New - new
func New(b []byte) *Packet {
	var ret Packet
	decoder := gob.NewDecoder(bytes.NewBuffer(b))
	err := decoder.Decode(&ret)
	if err != nil {
		log.Panicln("Failed to parse received packet\nError: ", err)
	}
	return &ret
}

// Encode - Encode
func (p *Packet) Encode() []byte {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)
	encoder.Encode(p)
	return b.Bytes()
}

// AddContent - Add content
func (p *Packet) AddContent(i interface{}) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)
	encoder.Encode(i)
	p.Content = b.Bytes()
}

// ParseContent - Parse content
func (p *Packet) ParseContent() (interface{}, error) {
	decoder := gob.NewDecoder(bytes.NewBuffer(p.Content))
	switch p.Type {
	case Handshake:
		var ret HandshakeMessage
		err := decoder.Decode(&ret)
		return ret, err
	case Init:
		var ret InitMessage
		err := decoder.Decode(&ret)
		return ret, err
	case Ack:
		return AckMessage{}, nil
	case Sync:
		fallthrough
	case Replay:
		var ret ReplayMessage
		err := decoder.Decode(&ret)
		return ret, err
	case Content:
		var ret ContentMessage
		err := decoder.Decode(&ret)
		return ret, err
	}
	return nil, errors.New("Invalid type")
}

// ParsePacket - Parse packet
func ParsePacket(b []byte) (*Packet, error) {
	decoder := gob.NewDecoder(bytes.NewBuffer(b))
	var ret Packet
	err := decoder.Decode(&ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}
