/*
Package redhed is Redundant Header file format.
*/

package redhed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/base64"
	"io"
	"log"
	"strings"
)

// We choose these:
const Magic = 52022

var Ian = binary.LittleEndian

// AES256 and GCM mode dictate these:
const KeyLen = 32
const BlockLen = 16
const GcmOverhead = 16

// With 4K disk allocations, we derive these:
const ChunkLen = 4096
const HeadLen = 16
const EncLen = ChunkLen - HeadLen - GcmOverhead
const MiddleLen = 20
const PathAndPayloadLen = EncLen - MiddleLen

const MaxTime = (1 << 48) - 1
const MaxSize = (1 << 48) - 1
const MaxPathLen = (1 << 16) - 1

func Len(b []byte) int64 {
	return int64(len(b))
}
func SLen(s string) int64 {
	return int64(len(s))
}

// check sizes of headers.
func init() {
	a := binary.Size(new(MiddleBin))
	if a != MiddleLen {
		log.Panicln(a)
	}
	b := binary.Size(new(IVHead))
	if b != HeadLen {
		log.Panicln(b)
	}
}

type Key struct {
	ID  uint16
	PW  []byte // Delete this later.
	AES cipher.Block
	GCM cipher.AEAD
}

type IVHead struct {
	Magic uint16   // 0
	KeyID uint16   // 2
	Nonce [12]byte // 4
} // 16

func (o *IVHead) FromBytes(b []byte) {
	bb := bytes.NewBuffer(b)
	err := binary.Read(bb, Ian, o)
	if err != nil {
		log.Panicln(err)
	}
}
func (o *IVHead) Bytes() []byte {
	var bb bytes.Buffer
	binary.Write(&bb, Ian, o)
	return bb.Bytes()
}

type MiddleBin struct {
	Time    uint32 // 0
	XTime   uint16 // 4
	Size    uint32 // 6
	XSize   uint16 // 10
	Offset  uint32 // 12
	XOffset uint16 // 16

	PathLen uint16 // 18
} // 20

type Holder struct {
	Time    int64
	Size    int64
	Offset  int64
	Path    string
	Payload []byte
}

// PayloadLen is a function of the path length.
// The bigger the path, the smaller the payload.
func PayloadLenFromPath(path string) int64 {
	n := SLen(path)
	if n > MaxPathLen {
		log.Panicln("bad len(path)")
	}
	return PathAndPayloadLen - SLen(path)
}

func (h *Holder) FromBytes(b []byte) {
	buf := bytes.NewBuffer(b)
	if buf.Len() != EncLen {
		log.Panicf("got %d want %d", buf.Len(), EncLen)
	}

	var m MiddleBin
	err := binary.Read(buf, Ian, &m)
	if err != nil {
		log.Panicln(err)
	}
	if buf.Len() != EncLen-MiddleLen {
		log.Panicf("got %d want %d", buf.Len(), EncLen-MiddleLen)
	}

	h.Time = (int64(m.XTime) << 32) + int64(m.Time)
	h.Size = (int64(m.XSize) << 32) + int64(m.Size)
	h.Offset = (int64(m.XOffset) << 32) + int64(m.Offset)
	plen := int(m.PathLen)

	bp := make([]byte, plen)
	n, err := buf.Read(bp)
	if err != nil {
		log.Panicln(err)
	}
	if n != len(bp) {
		log.Panicf("got %d want %d", n, plen)
	}
	h.Path = string(bp)
	if int64(buf.Len()) != PayloadLenFromPath(h.Path) {
		log.Panicf("got %d want %d", buf.Len(), PayloadLenFromPath(h.Path))
	}

	h.Payload = buf.Bytes()
	if Len(h.Payload) != PayloadLenFromPath(h.Path) {
		log.Panicf("got %d want %d", Len(h.Payload), PayloadLenFromPath(h.Path))
	}
}

func (h *Holder) Bytes() []byte {
	time, size, offset, path := h.Time, h.Size, h.Offset, h.Path

	if time < 0 || time > MaxTime {
		log.Panicf("bad time: %d", time)
	}
	if size < -1 || size > MaxSize {
		log.Panicf("bad size: %d", size)
	}
	if offset < 0 || offset > MaxSize {
		log.Panicf("bad offset: %d", offset)
	}
	if len(path) > MaxPathLen {
		log.Panicf("bad offset: %d %q", len(path), path)
	}

	var m MiddleBin
	m.Time = uint32(time)
	m.XTime = uint16(time >> 32)
	m.Size = uint32(size)
	m.XSize = uint16(size >> 32)
	m.Offset = uint32(offset)
	m.XOffset = uint16(offset >> 32)
	m.PathLen = uint16(len(path))

	var z bytes.Buffer       // Accumulate result.
	binary.Write(&z, Ian, m) // Write middle.
	z.Write([]byte(h.Path))  // Write path.
	z.Write(h.Payload)       // Write payload.

	want := PayloadLenFromPath(h.Path)
	got := Len(h.Payload)
	if want < got {
		log.Panicf("want %d < got %d", want, got)
	}
	if want > got {
		z.Write(make([]byte, want-got)) // Write zero-fill.
	}
	return z.Bytes()
}

func NewKey(id uint16, pw []byte) *Key {
	var err error
	z := &Key{ID: id, PW: pw}
	z.AES, err = aes.NewCipher(pw)
	if err != nil {
		log.Panicln(err)
	}
	z.GCM, err = cipher.NewGCM(z.AES)
	if err != nil {
		log.Panicln(err)
	}
	return z
}

func SealChunk(key *Key, in []byte) []byte {
	if len(in) != EncLen {
		log.Panicln("bad len(in)")
	}
	h := IVHead{Magic: Magic, KeyID: key.ID}
	_, err := rand.Read(h.Nonce[:])
	if err != nil {
		log.Panicln(err)
	}
	var buf bytes.Buffer
	err = binary.Write(&buf, Ian, h)
	if err != nil {
		log.Panicln(err)
	}
	zzz := key.GCM.Seal(h.Bytes(), h.Nonce[:], in, nil)
	return zzz
}

func OpenChunk(key *Key, in []byte) *Holder {
	if len(in) != ChunkLen {
		log.Panicln("bad len(in)")
	}
	head := &IVHead{}
	head.FromBytes(in[:16])
	if head.Magic != Magic {
		log.Panicf("bad Chunk Magic: got %d want %d", head.Magic, Magic)
	}
	if head.KeyID != key.ID {
		log.Panicf("bad Chunk Key ID: got %d want %d", head.KeyID, key.ID)
	}

	z, err := key.GCM.Open(nil, head.Nonce[:], in[16:], nil)
	if err != nil {
		log.Panicln(err)
	}
	h := &Holder{}
	h.FromBytes(z)
	return h
}

////////////

type rReader struct {
	fd     io.ReaderAt // ReadAt(p []byte, off int64) (n int, err error)
	pos    int64
	key    *Key
	payLen int64
	buf    []byte
	sector int64
	eof    bool
	time   int64
	size   int64
}

func NewReader(fd io.ReaderAt, key *Key) io.ReadCloser {
	return &rReader{
		fd:  fd,
		key: key,
	}
}

type rWriter struct {
	fd   io.WriterAt
	key  *Key
	path string
	time int64

	payLen int64
	buf    []byte
	sector int64
}

func NewWriter(fd io.WriterAt, key *Key, path string, time int64) io.WriteCloser {
	z := &rWriter{
		fd:     fd,
		key:    key,
		path:   path,
		time:   time,
		payLen: PayloadLenFromPath(path),
	}
	return z
}

func (o *rWriter) Write(p []byte) (int, error) {
	o.buf = append(o.buf, p...)
	o.pushWholeSectors()
	return len(p), nil
}
func (o *rWriter) Close() error {
	o.pushFinal()
	return nil
}
func (o *rWriter) pushWholeSectors() {
	for Len(o.buf) > o.payLen { // Might leave one whole sector, when Len(o.buf) == o.payLen.
		off := o.sector * o.payLen
		h := Holder{
			Time:    o.time,
			Size:    -1,
			Offset:  off,
			Path:    o.path,
			Payload: o.buf[:o.payLen],
		}
		o.EncryptSectorAndWrite(h)
		o.buf = o.buf[o.payLen:]
	}
}

func (o *rWriter) pushFinal() {
	o.pushWholeSectors() // Leaves 1 to o.payLen bytes in o.buf, or even 0 if file sz == 0.
	off := o.sector * o.payLen
	sz := off + Len(o.buf)
	o.buf = append(o.buf, make([]byte, o.payLen-Len(o.buf))...) // zero pad.
	h := Holder{
		Time:    o.time,
		Size:    sz,
		Offset:  off,
		Path:    o.path,
		Payload: o.buf,
	}
	o.EncryptSectorAndWrite(h)
	o.buf = o.buf[o.payLen:]
}

func (o *rReader) Close() error {
	return nil
}
func (o *rReader) Read(p []byte) (int, error) {
	yet := len(p) // Num bytes yet to do.
	done := 0

	for yet > 0 {
		if len(o.buf) > 0 {
			// Copy returns the number of elements copied,
			// which will be the minimum of len(src) and len(dst).
			c := copy(p[done:], o.buf)
			o.buf = o.buf[c:]
			yet -= c
			done += c
		} else if o.eof {
			break
		} else {
			h := o.ReadAndDecryptSector()
			o.time = h.Time
			o.size = h.Size
			o.buf = h.Payload
			if h.Size != 0xFFFFffffFFFF {
				gap := h.Size - h.Offset
				if gap <= Len(o.buf) {
					o.buf = o.buf[:gap]
					o.eof = true
				}
			}
		}
	}
	if done == 0 && o.eof {
		return 0, io.EOF
	}
	return done, nil
}

func (o *rReader) ReadAndDecryptSector() (h *Holder) {
	chunk := make([]byte, ChunkLen)
	n, err := o.fd.ReadAt(chunk, o.sector*ChunkLen)
	if err != nil {
		log.Panicln(err)
	}
	if n != ChunkLen {
		log.Panicf("short read in ReadAndDecryptSector: %d", n)
	}
	o.sector++

	return OpenChunk(o.key, chunk)
}

func (o *rWriter) EncryptSectorAndWrite(h Holder) {
	plain := h.Bytes()
	chunk := SealChunk(o.key, plain)
	n, err := o.fd.WriteAt(chunk, o.sector*ChunkLen)
	o.sector++
	if err != nil {
		log.Panicln(err)
	}
	if n != ChunkLen {
		log.Panicf("short write in EncryptSectorAndWrite: %d", n)
	}
}

func EncryptFilename(name string, key *Key) string {
  // Create random 96-byt nonce, for 128-bit IV. 
  nonce := make([]byte, 12)
	c, err := rand.Read(nonce)
	if err != nil {
		log.Panicln(err)
	}
  if c != 12 {
		log.Panicln("bad rand.Read")
  }
  iv := make([]byte, 16)
  copy(iv, nonce)

  blocks := []byte(name)
  residue := len(blocks) & 15
  if residue != 0 {
    // Pad final block with NULs.
    blocks = append(blocks, make([]byte, 16 - residue)...)
  }

  en := cipher.NewCBCEncrypter(key.AES, iv)
  en.CryptBlocks(blocks, blocks)

  var bits []byte
  bits = append(bits, nonce...)
  bits = append(bits, blocks...)
  dark := base64.URLEncoding.EncodeToString(bits)
  return dark
}

func DecryptFilename(dark string, key *Key) string {
  x, err := base64.URLEncoding.DecodeString(dark)
	if err != nil {
		log.Panicln(err)
	}

  nonce := x[:12]
  iv := make([]byte, 16)
  copy(iv, nonce)

  de := cipher.NewCBCDecrypter(key.AES, iv)
  de.CryptBlocks(x[12:], x[12:])

  return strings.TrimRight(string(x[12:]), "\000")
}
