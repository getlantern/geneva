// Package internal provides internal Geneva types and functions.
package internal

import (
	"errors"
	"io"
)

type OnesComplementChecksum struct {
	chksum uint16
}

func (c *OnesComplementChecksum) Add(n uint16) uint16 {
	chksum := uint32(c.chksum) + uint32(n)
	for chksum > 0xffff {
		chksum = (chksum & 0xffff) + (chksum >> 16)
	}

	c.chksum = uint16(chksum)

	return c.chksum
}

func (c *OnesComplementChecksum) Finalize() uint16 {
	return ^c.chksum
}

func EOFUnexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}

	return err
}
