package internal

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
