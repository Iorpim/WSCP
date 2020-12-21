package packet

// Message - Message
type Message interface {
	Encode() []byte
}

// HandshakeMessage - Handshake message
type HandshakeMessage struct {
	PubKey []byte
	Key    []byte
}

// InitMessage - Init message
type InitMessage struct {
	Size        int
	Filename    string
	Checksum    string
	PacketCount int
	Index       int
}

// AckMessage - Ack message
type AckMessage struct {
}

// SyncMessage - Sync message
type SyncMessage struct {
	Index    int
	Checksum string
}

// ReplayMessage - Replay message
type ReplayMessage = SyncMessage

// ContentMessage - Content message
type ContentMessage struct {
	Content  []byte
	Checksum string
}
