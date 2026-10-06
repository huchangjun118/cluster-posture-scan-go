package object

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func newDecoder(data []byte) *json.Decoder {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
