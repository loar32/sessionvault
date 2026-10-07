// Ключ восстановления: 256 бит в виде 24 слов BIP-39 (английский список) с контрольной суммой от опечаток.
package recovery

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"github.com/loar32/sessionvault/internal/i18n"
	"strings"
)

//go:embed english.txt
var wordsFile string

var words = strings.Fields(wordsFile)

const (
	KeySize   = 32
	wordCount = 24
)

var ErrInvalid = errors.New("ключ восстановления введён неверно: нужно 24 слова из списка BIP-39 без опечаток")

// Words превращает 32 случайных байта в 24 слова.
func Words(key []byte) (string, error) {
	if len(key) != KeySize {
		return "", errors.New(i18n.T("ключ восстановления должен быть 32 байта"))
	}
	sum := sha256.Sum256(key)
	bits := append(append([]byte{}, key...), sum[0])
	out := make([]string, wordCount)
	for i := range out {
		n := 0
		for j := 0; j < 11; j++ {
			p := i*11 + j
			n = n<<1 | int(bits[p/8]>>(7-p%8)&1)
		}
		out[i] = words[n]
	}
	return strings.Join(out, " "), nil
}

// Parse принимает слова через любые пробелы и в любом регистре; проверяет контрольную сумму.
func Parse(s string) ([]byte, error) {
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) != wordCount {
		return nil, ErrInvalid
	}
	bits := make([]byte, (wordCount*11+7)/8)
	for i, w := range fields {
		n := -1
		for k, x := range words {
			if x == w {
				n = k
				break
			}
		}
		if n < 0 {
			return nil, ErrInvalid
		}
		for j := 0; j < 11; j++ {
			if n>>(10-j)&1 == 1 {
				p := i*11 + j
				bits[p/8] |= 1 << (7 - p%8)
			}
		}
	}
	key := bits[:KeySize]
	if sum := sha256.Sum256(key); sum[0] != bits[KeySize] {
		return nil, ErrInvalid
	}
	return key, nil
}
