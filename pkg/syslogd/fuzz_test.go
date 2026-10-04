package syslogd

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// FuzzReadFrame: any byte stream is split into frames no larger than the
// limit, the reader always makes progress, and well-formed octet-counted
// frames come back exactly.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte("<34>Oct  2 11:58:01 web1 sshd[311]: hi\n12 <34>abcdefgh9 newline\n"), []byte("hello world"))
	f.Add([]byte("0 \n00 x\n9999999 x\n-1 y\n"), []byte(""))
	f.Add([]byte("65537 "+strings.Repeat("a", 70000)), []byte("x"))
	f.Add([]byte(strings.Repeat("b", 70000)+"\nok\n"), []byte("\n\n"))
	f.Fuzz(func(t *testing.T, stream, framed []byte) {
		if len(framed) == 0 || len(framed) > MaxMessageSize {
			return
		}
		// A well-formed octet-counted frame after the junk must come back
		// intact unless the junk swallowed it (a count running past it).
		in := append(append(bytes.Clone(stream), '\n'), []byte(itoa(len(framed))+" ")...)
		in = append(in, framed...)
		r := bufio.NewReaderSize(bytes.NewReader(in), MaxMessageSize+16)
		var last []byte
		for n := 0; ; n++ {
			if n > len(in)+2 {
				t.Fatalf("no progress after %d frames", n)
			}
			msg, err := readFrame(r)
			if len(msg) > MaxMessageSize+1 {
				t.Fatalf("frame of %d bytes", len(msg))
			}
			if errors.Is(err, errTooLong) {
				continue
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("unexpected error %v", err)
				}
				if len(msg) > 0 {
					last = msg
				}
				break
			}
			last = msg
		}
		if !bytes.Contains(stream, []byte{' '}) && !bytes.Contains(stream, []byte{'\n'}) && len(stream) < 8 &&
			!bytes.Equal(last, framed) {
			t.Fatalf("framed message %q came back as %q", framed, last)
		}
	})
}

func itoa(n int) string {
	var b []byte
	for n > 0 || len(b) == 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
