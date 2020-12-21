package rsa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"log"
)

type aesProvider struct {
	C   cipher.Block
	GCM cipher.AEAD
}

// RSA - RSA
type RSA struct {
	// Pubkey - Public key
	Pubkey  *rsa.PublicKey
	privKey *rsa.PrivateKey
	aes     *aesProvider
}

// New - New public key-only RSA instance
func New(b []byte) *RSA {
	pubkey, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		log.Fatal("Failed to parse public key\nError: ", err)
	}
	return &RSA{
		Pubkey:  pubkey.(*rsa.PublicKey),
		privKey: nil,
	}
}

// GenerateKeys - Generate keys
func GenerateKeys() *RSA {
	keys, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal("Failed to generate keys!\nError: ", err)
	}
	return &RSA{
		Pubkey:  &keys.PublicKey,
		privKey: keys,
	}
}

// GenerateSymmetricKey - Generate AES symmetric key
func (r *RSA) GenerateSymmetricKey() []byte {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		log.Fatalln("Failed to generate symmetric key\nError: ", err)
	}

	r.SetSymmetricKey(key)

	return key
}

// SetSymmetricKey - Set symmetric key
func (r *RSA) SetSymmetricKey(b []byte) {
	c, err := aes.NewCipher(b)
	if err != nil {
		log.Fatalln("Failed to generate AES cipher instance\nError: ", err)
	}
	r.aes = &aesProvider{
		C: c,
	}

	r.aesInit()
}

func (r *RSA) aesInit() {
	g, err := cipher.NewGCM(r.aes.C)
	if err != nil {
		log.Fatalln("Failed to initiate GCM cipher mode\nError: ", err)
	}

	r.aes.GCM = g
}

func (r *RSA) generateNonce() []byte {
	n := make([]byte, r.aes.GCM.NonceSize())
	_, err := rand.Read(n)
	if err != nil {
		log.Fatalln("Failed to generate GCM nonce\nError: ", err)
	}

	return n
}

func (r *RSA) aesEncrypt(b []byte) []byte {
	n := r.generateNonce()

	return r.aes.GCM.Seal(n, n, b, nil)
}

func (r *RSA) aesDecrypt(b []byte) []byte {
	n, b := b[:r.aes.GCM.NonceSize()], b[r.aes.GCM.NonceSize():]

	ret, err := r.aes.GCM.Open(nil, n, b, nil)
	if err != nil {
		log.Fatalln("Failed to decrypt message\nError: ", err)
	}
	return ret
}

// Encrypt - Encrypt
func (r *RSA) Encrypt(b []byte) []byte {
	// If symmetric key has already been exchanged, use AES instead
	if r.aes != nil {
		return r.aesEncrypt(b)
	}
	if r.Pubkey == nil {
		return nil
	}
	ret, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, r.Pubkey, b, nil)
	if err != nil {
		log.Panicln("Failed to encrypt message!\nError: ", err)
	}
	return ret
	// return base64.StdEncoding.EncodeToString(ret)
}

// Required intermediate for PubDecrypt to exist,
// as RSA.privKey is unexported
func rsaDecrypt(b []byte, key *rsa.PrivateKey) []byte {
	//b, _ := base64.StdEncoding.DecodeString(s)
	ret, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, key, b, nil)
	if err != nil {
		log.Panicln("Failed to decrypt message\nError: ", err)
		return nil
	}
	return ret
}

// PubEncrypt - Force RSA usage
func (r *RSA) PubEncrypt(b []byte) []byte {
	t := RSA{
		Pubkey: r.Pubkey,
	}

	return t.Encrypt(b)
}

// PubDecrypt - Force RSA usage
func (r *RSA) PubDecrypt(b []byte) []byte {
	return rsaDecrypt(b, r.privKey)
}

// Decrypt - Decrypt
func (r *RSA) Decrypt(b []byte) []byte {
	if r.aes != nil {
		return r.aesDecrypt(b)
	}
	return rsaDecrypt(b, r.privKey)
}

// Bytes - Returns public key's bytes
func (r *RSA) Bytes() []byte {
	ret, _ := x509.MarshalPKIXPublicKey(r.Pubkey)
	return ret
}
