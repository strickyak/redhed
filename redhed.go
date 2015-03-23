/*
Package redhed is Redundant Header file format.
*/

package redhed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	//P "path"
	F "path/filepath"
	"strconv"
	"strings"
	"time"
)

// Magic1 uses the key for all chunks.
const Magic1 = 32021 // od -c: "0000000 025   }"
// Magic2 derives a new key for each chunk.
const Magic2 = 32020 // od -c: "0000000 025   |"

var Ian = binary.LittleEndian

// AES256 and GCM mode dictate these:
const KeyLen = 32
const BlockLen = 16
const GcmOverhead = 16

// With 4K disk allocations, we derive these:
const ChunkLen = 4096
const HeadLen = 16
const EncLen = ChunkLen - HeadLen - GcmOverhead
const MiddleLen = 36
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
	ID  int16
	PW  []byte // Delete this later.
	AES cipher.Block
	GCM cipher.AEAD
}

type IVHead struct {
	Magic int16    // 0
	KeyID int16    // 2
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
	Time    uint32   // 0  // TODO: Millis
	XTime   uint16   // 4
	Size    uint32   // 6
	XSize   uint16   // 10
	Offset  uint32   // 12
	XOffset uint16   // 16
	Hash    [16]byte // 18

	PathLen uint16 // 34
} // 36 was 20

type Holder struct {
	Time    int64 // TODO: Millis
	Size    int64
	Offset  int64
	Hash    [16]byte
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
	h.Hash = m.Hash
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
	m.Hash = h.Hash
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

func NewKey(id string, pw []byte) *Key {
	var err error
	z := &Key{ID: DecodeKeyID(id), PW: pw}
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
func HashJoin(sz int, data ...[]byte) []byte {
	hasher := sha256.New()
	for _, x := range data {
		xlen, err := hasher.Write(x)
		if err != nil {
			panic(err)
		}
		if xlen != len(x) {
			panic("Short Write on md5")
		}
	}
	return hasher.Sum(nil)[:sz]
}

func DeriveKey(base *Key, varient []byte) *Key {
	pw2 := HashJoin(32, base.PW, varient)
	z := &Key{ID: base.ID, PW: pw2}
	var err error
	z.AES, err = aes.NewCipher(pw2)
	if err != nil {
		log.Panicln(err)
	}
	z.GCM, err = cipher.NewGCM(z.AES)
	if err != nil {
		log.Panicln(err)
	}
	return z
}

func SealChunk(key *Key, magic int16, in []byte) []byte {
	if len(in) != EncLen {
		log.Panicln("bad len(in)")
	}
	h := IVHead{KeyID: key.ID}
	n, err := rand.Read(h.Nonce[:])
	if err != nil {
		log.Panicln(err)
	}
	if n != 12 {
		log.Panicf("short read: %d", n)
	}
	switch magic {
	case Magic1:
		h.Magic = Magic1
	case Magic2:
		h.Magic = Magic2
		key = DeriveKey(key, h.Nonce[:])
	default:
		log.Panicf("bad magic: %d", magic)
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
	if head.KeyID != key.ID {
		log.Panicf("bad Chunk Key ID: got %d want %d", head.KeyID, key.ID)
	}
	switch head.Magic {
	case Magic1:

	case Magic2:
		key = DeriveKey(key, head.Nonce[:])
	default:
		log.Panicf("bad Chunk Magic: got %d", head.Magic)
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
	hash   [16]byte
}

// NewReader returns ReadCloser, ReadSeeker, and ReaderAt.
func NewReader(fd io.ReaderAt, key *Key) *rReader {
	o := &rReader{
		fd:  fd,
		key: key,
	}
	o.Pull()
	println("rReader::New", o.fd)
	return o
}

func (o *rReader) TimeSizeHash() (int64, int64, []byte) {
	return o.time, o.size, o.hash[:]
}

type rWriter struct {
	fd    io.WriterAt
	key   *Key
	path  string
	time  int64
	size  int64
	hash  [16]byte
	magic int16

	payLen int64
	buf    []byte
	sector int64
}

func NewWriter(fd io.WriterAt, key *Key, magic int16, path string, time int64, size int64, hash [16]byte) io.WriteCloser {
	z := &rWriter{
		fd:     fd,
		key:    key,
		magic:  magic,
		path:   path,
		time:   time,
		size:   size,
		hash:   hash,
		payLen: PayloadLenFromPath(path),
	}
	return z
}

func (o *rWriter) Write(p []byte) (int, error) {
	//log.Printf("rWriter::Write << %d bytes", len(p))
	o.buf = append(o.buf, p...)
	o.pushWholeSectors()
	//log.Printf("rWriter::Write >> Wrote %d", len(p))
	return len(p), nil
}
func (o *rWriter) Close() error {
	//log.Printf("rWriter::Write Close...")
	o.pushFinal()
	//log.Printf("rWriter::Write Close... Pushed.")
	return nil
}
func (o *rWriter) pushWholeSectors() {
	//log.Printf("rWriter::pushWholeSectors: Len(o.buf) = %d", Len(o.buf))
	for Len(o.buf) > o.payLen { // Might leave one whole sector, when Len(o.buf) == o.payLen.
		off := o.sector * o.payLen
		h := Holder{
			Time:    o.time,
			Size:    o.size,
			Offset:  off,
			Hash:    o.hash,
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
	if sz != o.size {
		log.Panicf("Got size %d, but declared size %d", sz, o.size)
	}
	o.buf = append(o.buf, make([]byte, o.payLen-Len(o.buf))...) // zero pad.
	h := Holder{
		Time:    o.time,
		Size:    o.size,
		Hash:    o.hash,
		Offset:  off,
		Path:    o.path,
		Payload: o.buf,
	}
	o.EncryptSectorAndWrite(h)
	o.buf = o.buf[o.payLen:]
}

func (o *rReader) Close() error {
	println("rReader::Close", o.fd)
	if rc, ok := o.fd.(io.ReadCloser); ok {
		rc.Close()
	}
	return nil
}
func (o *rReader) Seek(offset int64, whence int) (int64, error) {
	println("rReader::Seek", offset, whence, o.fd)
	var off int64
	switch whence {
	case 0:
		off = offset
	case 1:
		off = o.pos + offset
	case 2:
		off = o.size + offset
	default:
		return 0, errors.New("Bad whence")
	}

	if off < 0 {
		return 0, errors.New("Negative offset")
	}

	if off == 0 {
		*o = *NewReader(o.fd, o.key)
		return 0, nil
	}

	bb := make([]byte, 1)
	_, err := o.ReadAt(bb, off-1)
	if err != nil {
		return 0, err
	}
	return off, nil
}

func (o *rReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off != o.pos {
		// Stupid but easy.  TODO: Better.
		*o = *NewReader(o.fd, o.key)
		for o.pos < off {
			// Read and throw away bytes until o.pos == off.
			gap := off - o.pos
			if gap > ChunkLen {
				gap = ChunkLen
			}
			bb := make([]byte, gap)
			c, err := o.Read(bb)
			if err != nil && c == 0 {
				return 0, err
			}
		}
	}
	return o.Read(p)
}

func (o *rReader) Read(p []byte) (int, error) {
	yet := len(p) // Num bytes yet to do.
	done := 0

	for yet > 0 {
		if len(o.buf) > 0 {
			// Copy returns the number of elements copied,
			// which will be the minimum of len(src) and len(dst).
			c := copy(p[done:], o.buf)
			o.pos += int64(c)
			o.buf = o.buf[c:]
			yet -= c
			done += c
		} else if o.eof {
			break
		} else {
			o.Pull()
		}
	}
	if done == 0 && o.eof {
		return 0, io.EOF
	}
	return done, nil
}

func (o *rReader) Pull() {
	h := o.ReadAndDecryptSector()
	o.time = h.Time
	o.size = h.Size
	o.hash = h.Hash
	o.buf = h.Payload
	if h.Size != 0xFFFFffffFFFF {
		gap := h.Size - h.Offset
		if gap <= Len(o.buf) {
			o.buf = o.buf[:gap]
			o.eof = true
		}
	}
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
	chunk := SealChunk(o.key, o.magic, plain)
	n, err := o.fd.WriteAt(chunk, o.sector*ChunkLen)
	//log.Printf("rWriter::EncryptSectorAndWrite: wrote %d bytes, sector %d, err %q", n, o.sector, StrErr(err))
	o.sector++
	if err != nil {
		log.Panicln(err)
	}
	if n != ChunkLen {
		log.Panicf("short write in EncryptSectorAndWrite: %d", n)
	}
}

// GetEncryptedPath returns an encrypted path relative to topname.
func GetEncryptedPath(topname, pathname string, key *Key) string {
	//log.Printf("GetEncryptedPath: topname %q pathname %q key %d", topname, pathname, key.ID)
	if topname == "." {
		panic("WTF")
	}
	if pathname == "" {
		panic("WTF")
	}
	if pathname == "." {
		panic("WTF")
	}
	var zz []string
	t := topname
	w := strings.Split(pathname, "/")
	for _, e := range w {
		//log.Printf("GetEncryptedPath: step [%d] %q ...", i, e)
		if e == "" || e == "." {
			continue
		}
		if strings.HasPrefix(e, "%") {
			panic("GetEncryptedPath: plaintext has prefix %: <<< " + pathname)
		}
		x := ""
		gg, err := F.Glob(F.Join(t, "%*"))
		if err != nil {
			panic(err)
		}
		for _, g := range gg {
			gb := F.Base(g)
			//log.Printf("GetEncryptedPath: step [%d] %q Considering: %q", i, e, gb)
			if DecryptFilename(gb, key) == e {
				x = gb
				//log.Printf("GetEncryptedPath: step [%d] %q USING: %q", i, e, gb)
				break
			}
		}
		if x == "" {
			x = EncryptFilename(e, key)
			//log.Printf("GetEncryptedPath: step [%d] %q GENERATING: %q", i, e, x)
		}
		zz = append(zz, x)
		t = F.Join(t, x)
	}

	z := strings.Join(zz, "/")
	// log.Printf("GetEncryptedPath returns: %q %q >>> %q", topname, pathname, z)
	return z
}

func EncryptFilename(name string, key *Key) string {
	// As a bit of a sanity check, forbid ctrl chars in name.
	for _, ch := range name {
		if ch < 32 {
			log.Panicf("EncryptFilename: Bad char in filename, ch = %d", ch)
		}
	}

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
		blocks = append(blocks, make([]byte, 16-residue)...)
	}

	en := cipher.NewCBCEncrypter(key.AES, iv)
	en.CryptBlocks(blocks, blocks)

	var bits []byte
	bits = append(bits, nonce...)
	bits = append(bits, blocks...)
	dark := "%" + base64.URLEncoding.EncodeToString(bits)
	//log.Printf("EncryptFilename returns: key=%d %q >>> %q", key.ID, name, dark)
	return dark
}

func DecryptFilename(dark string, key *Key) string {
	//log.Printf("DecryptFilename: %q %d", dark, key.ID)
	if !strings.HasPrefix(dark, "%") {
		log.Panicf("W/ DecryptFilename: does not have prefix '%%': %q", dark)
		return ""
	}
	if len(dark) < 40 {
		log.Panicf("W/ DecryptFilename: too short: %q", dark)
		return ""
	}

	x, err := base64.URLEncoding.DecodeString(dark[1:])
	if err != nil {
		log.Panicf("W/ base64.URLEncoding.DecodeString: %s", err.Error())
		return ""
	}

	nonce := x[:12]
	iv := make([]byte, 16)
	copy(iv, nonce)

	de := cipher.NewCBCDecrypter(key.AES, iv)
	de.CryptBlocks(x[12:], x[12:])

	name := strings.TrimRight(string(x[12:]), "\000")
	// As a bit of a sanity check, forbid ctrl chars in name.
	for _, ch := range name {
		if ch < 32 {
			log.Panicf("W/ DecryptFilename: Bad char in filename, ch = %d", ch)
			return ""
		}
	}

	//log.Printf("DecryptFilename returns: key=%d %q >>> %q", key.ID, dark, name)
	return name
}

// Encode5bits encodes the lowest 5 bits as a letter 'A'..'Z', but values {0, 27..31} panic.
func Encode5bits(n int16) byte {
	n &= 31 // Use 5 low bits.
	if 1 <= n && n <= 26 {
		return byte(n - 1 + 'A') // 1 .. 26 -> 'A' .. 'Z'
	}
	panic(fmt.Sprintf("Encode5bits: Bad input %d.", n))
}

// Only defined on A..Z (case independant)
func Decode5bits(c byte) int16 {
	if 'A' <= c && c <= 'Z' {
		return int16(c) - 'A' + 1
	}
	if 'a' <= c && c <= 'z' {
		return int16(c) - 'a' + 1
	}
	panic(fmt.Sprintf("Decode5bits: Bad byte %d.", c))
}

// EncodeKeyID is the inverse of DecodeKeyID.
// Not all int16s are allowed; some will panic.
func EncodeKeyID(n int16) string {
	if n >= 0 {
		return fmt.Sprintf("%d", n)
	} else {
		return string([]byte{
			Encode5bits(n >> 10),
			Encode5bits(n >> 5),
			Encode5bits(n)})
	}
}

// DecodeKeyID takes ASCII integers "0".."32767" or 3 letters 'AAA'..'ZZZ'.
// ASCII integers encode to positive int16s; 3 letters to negative int16s.
// Not all negative int16s are possible, but base32 digits could be ambiguous.
func DecodeKeyID(s string) int16 {
	n, err := strconv.Atoi(s)
	if err == nil {
		if n < 0 || n > 32767 {
			panic("DecodeKeyID: Bad ASCII integer: " + s)
		}
		return int16(n)
	}
	if len(s) != 3 {
		panic("DecodeKeyID: Bad non- ASCII integer: " + s)
	}
	return int16(-32768) | (Decode5bits(s[0]) << 10) | (Decode5bits(s[1]) << 5) | Decode5bits(s[2])
}

type StreamWriter struct {
	key    *Key
	tmpkey *Key
	tmpfd  *os.File
	hasher hash.Hash
	w      io.Writer
	magic  int16

	MTimeMillis int64
	Size        int64
	Hash        [16]byte
	Topname     string
	RawDest     string
	tempname    string
	fnGetName   func(*StreamWriter) string
}

// NewStreamWriter() gives you a Writer that you can write and close, before you need to decide the filaname.
// Also it lets you put the correct final hash & size in each redhed block.
func NewStreamWriter(topname string, key *Key, magic int16, mtimeMillis int64, fnGetName func(*StreamWriter) string) *StreamWriter {
	tmppw := make([]byte, 32)
	rand.Read(tmppw)
	tmpkey := NewKey("0", tmppw)

	tempbb := make([]byte, 8)
	rand.Read(tempbb)
	temp := hex.EncodeToString(tempbb)
	tempname := F.Join(topname, "__tmp."+temp)
	tmpfd, err := os.OpenFile(tempname, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		panic(err)
	}
	err = os.Remove(tempname)
	if err != nil {
		panic(err)
	}
	w := NewWriter(tmpfd, tmpkey, Magic1, "?", mtimeMillis, 0 /*Size*/, *new([16]byte) /*Hash*/)

	if mtimeMillis <= 0 {
		mtimeMillis = time.Now().Unix() * 1000
	}
	z := &StreamWriter{
		Topname:     topname,
		tempname:    tempname,
		hasher:      sha256.New(),
		tmpfd:       tmpfd,
		tmpkey:      tmpkey,
		key:         key,
		MTimeMillis: mtimeMillis,
		w:           w,
		fnGetName:   fnGetName,
		magic:       magic,
	}
	/*
		id := 999999999
		if key != nil {
			id = int(key.ID)
		}
		log.Printf("NewStreamWriter: top=%q key=%d mt=%d tmp=%s", topname, id, mtimeMillis, tempname)
	*/
	return z
}

func StrErr(e error) string {
	if e == nil {
		return "{*nil*}"
	}
	return "{*" + e.Error() + "*}"
}

func (o *StreamWriter) Write(p []byte) (int, error) {
	n, err := o.tmpfd.Write(p)
	// println("StreamWriter::Write: <<< ", len(p), " >>> ", n, StrErr(err))
	o.Size += int64(n)
	o.hasher.Write(p[:n])
	return n, err
}

func (o *StreamWriter) Close() (err error) {
	copy(o.Hash[:], o.hasher.Sum(nil)[:16])
	// println("StreamWriter::Close: final len:", o.Size, " final hash:", hex.EncodeToString(o.Hash[:]))
	r := o.tmpfd
	checkSize, err := r.Seek(0, 2)
	if err != nil {
		panic(err)
	}
	if checkSize != o.Size {
		log.Panicf("checkSize %d oSize %d", checkSize, o.Size)
	}
	r.Seek(0, 0)
	var dest string

	pathname := o.fnGetName(o)
	if pathname == "" {
		panic("WTF, empty")
	}
	println("o.fnGetName returns pathname: ", pathname)
	if o.key == nil {
		o.RawDest = pathname
		dest = F.Join(o.Topname, pathname)
		println("redhed.StreamWriter::Close: o.key==nil, RawDest: ", o.RawDest)
		println("redhed.StreamWriter::Close: o.key==nil, dest: ", dest)

		os.MkdirAll(F.Dir(dest), 0777)
		w, err := os.Create(dest)
		if err != nil {
			return err
		}

		n, err := io.Copy(w, r)
		log.Printf("redhed.StreamWriter::Close: io.Copy copied %d with err %q", n, StrErr(err))
		if err != nil {
			return err
		}

		checkSize, err := r.Seek(0, 2)
		if err != nil {
			panic(err)
		}
		if checkSize != o.Size {
			log.Panicf("checkSize %d oSize %d", checkSize, o.Size)
		}

		err = w.Close()
		log.Printf("redhed.StreamWriter::Close: Close >>> %q", StrErr(err))
		return err
	} else {
		o.RawDest = GetEncryptedPath(o.Topname, pathname, o.key)
		dest = F.Join(o.Topname, o.RawDest)
		println("redhed.StreamWriter::Close: RawDest:", o.RawDest)
		println("redhed.StreamWriter::Close: dest:", dest)
		os.MkdirAll(F.Dir(dest), 0777)
		wfd, err := os.Create(dest)
		if err != nil {
			return err
		}
		w := NewWriter(wfd, o.key, o.magic, pathname, o.MTimeMillis, o.Size, o.Hash)
		n, err := io.Copy(w, r)
		log.Printf("redhed.StreamWriter::Close: io.Copy copied %d with err %q", n, StrErr(err))
		if err != nil {
			return err
		}
		err = w.Close()
		log.Printf("redhed.StreamWriter::Close: Close >>> %q", StrErr(err))
		return err
	}
}
