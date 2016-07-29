package gopipt

import (
	"bufio"
	"io"
)

// ReadLiner produces lines for parsing. The returned lines are allowed to have
// trailing whitespace.
type ReadLiner interface {
	ReadLine() (string, error)
}

// BufLineReader implements ReadLiner for reading from an io.Reader.
type BufLineReader struct {
	buf *bufio.Reader
}

func NewBufLineReader(r io.Reader) *BufLineReader {
	return &BufLineReader{bufio.NewReader(r)}
}

func (r *BufLineReader) ReadLine() (string, error) {
	line, err := r.buf.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", err
	}
	return line, nil
}
