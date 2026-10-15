package crypto

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// Поток AES-GCM по блокам (схема STREAM): большие данные шифруются без загрузки целиком в память. Каждый блок — nonce и
// шифротекст; в AAD входят общий заголовок, номер блока и признак последнего блока. Поэтому блок нельзя переставить,
// взять из другого файла или отрезать хвост файла по границе блока.

const ChunkSize = 1 << 20

var ErrStream = errors.New("зашифрованный поток повреждён или подменён")

func chunkAAD(aad []byte, n uint64, last bool) []byte {
	b := binary.BigEndian.AppendUint64(append([]byte(nil), aad...), n)
	if last {
		return append(b, 1)
	}
	return append(b, 0)
}

type SealWriter struct {
	gcm cipher.AEAD
	aad []byte
	w   io.Writer
	buf []byte
	n   uint64
}

// NewSealWriter шифрует всё записанное в w. Close обязателен: он пишет последний блок.
func NewSealWriter(key, aad []byte, w io.Writer) (*SealWriter, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &SealWriter{gcm: gcm, aad: aad, w: w, buf: make([]byte, 0, ChunkSize)}, nil
}

// Полный блок уходит, только когда пришли следующие данные: какой блок последний, известно лишь в Close.
func (s *SealWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if len(s.buf) == ChunkSize {
			if err := s.flush(false); err != nil {
				return 0, err
			}
		}
		k := min(ChunkSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:k]...)
		p = p[k:]
	}
	return n, nil
}

func (s *SealWriter) Close() error {
	err := s.flush(true)
	Wipe(s.buf[:cap(s.buf)])
	return err
}

func (s *SealWriter) flush(last bool) error {
	nonce, err := random(s.gcm.NonceSize())
	if err != nil {
		return err
	}
	out := s.gcm.Seal(nonce, nonce, s.buf, chunkAAD(s.aad, s.n, last))
	Wipe(s.buf)
	s.buf = s.buf[:0]
	s.n++
	_, err = s.w.Write(out)
	return err
}

type OpenReader struct {
	gcm   cipher.AEAD
	aad   []byte
	r     *bufio.Reader
	frame []byte
	plain []byte
	rest  []byte
	n     uint64
	done  bool
}

// NewOpenReader расшифровывает поток NewSealWriter. Ошибка проверки любого блока — ErrStream; io.EOF приходит только
// после проверенного последнего блока.
func NewOpenReader(key, aad []byte, r io.Reader) (*OpenReader, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &OpenReader{gcm: gcm, aad: aad, r: bufio.NewReaderSize(r, 64<<10),
		frame: make([]byte, gcm.NonceSize()+ChunkSize+gcm.Overhead()), plain: make([]byte, 0, ChunkSize)}, nil
}

func (o *OpenReader) Read(p []byte) (int, error) {
	for len(o.rest) == 0 {
		if o.done {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			return 0, err
		}
	}
	k := copy(p, o.rest)
	o.rest = o.rest[k:]
	return k, nil
}

func (o *OpenReader) next() error {
	m, err := io.ReadFull(o.r, o.frame)
	last := false
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		last = true
	case err != nil:
		if errors.Is(err, io.EOF) {
			return ErrStream
		}
		return err
	default:
		if _, err := o.r.Peek(1); errors.Is(err, io.EOF) {
			last = true
		} else if err != nil {
			return err
		}
	}
	ns := o.gcm.NonceSize()
	if m < ns+o.gcm.Overhead() {
		return ErrStream
	}
	plain, err := o.gcm.Open(o.plain[:0], o.frame[:ns], o.frame[ns:m], chunkAAD(o.aad, o.n, last))
	if err != nil {
		return ErrStream
	}
	o.rest = plain
	o.n++
	o.done = last
	return nil
}

// Verify дочитывает поток до конца: так проверяется и последний блок, даже если потребитель (tar) остановился раньше.
func (o *OpenReader) Verify() error {
	_, err := io.Copy(io.Discard, o)
	return err
}

func (o *OpenReader) Close() {
	Wipe(o.plain[:cap(o.plain)])
	o.rest = nil
}
