// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package cmac implements the fast CMAC MAC based on
// a block cipher. This mode of operation fixes security
// deficiencies of CBC-MAC (CBC-MAC is secure only for
// fixed-length messages). CMAC is equal to OMAC1.
// This implementations supports block ciphers with a
// block size of:
//   - 64 bit
//   - 128 bit
//   - 160 bit
//   - 192 bit
//   - 224 bit
//   - 256 bit
//   - 320 bit
//   - 384 bit
//   - 448 bit
//   - 512 bit
//   - 768 bit
//   - 1024 bit
//   - 2048 bit
//
// Common ciphers like AES, Serpent etc. operate on 128 bit
// blocks. 256, 512 and 1024 are supported for the Threefish
// tweakable block cipher. Ciphers with 64 bit blocks are
// supported, but not recommened.
// CMAC (with AES) is specified in RFC 4493 and RFC 4494.
package cmac // import "github.com/aead/cmac"

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

var (
	zeros = make([]byte, 2048/8)

	rb_64   = []byte{0x00, 0x00, 0x1B}
	rb_128  = []byte{0x00, 0x00, 0x87}
	rb_160  = []byte{0x00, 0x00, 0x2D}
	rb_192  = []byte{0x00, 0x00, 0x87}
	rb_224  = []byte{0x00, 0x03, 0x09}
	rb_256  = []byte{0x00, 0x04, 0x25}
	rb_320  = []byte{0x00, 0x00, 0x1B}
	rb_384  = []byte{0x00, 0x10, 0x0D}
	rb_448  = []byte{0x00, 0x08, 0x51}
	rb_512  = []byte{0x00, 0x01, 0x25}
	rb_768  = []byte{0x0A, 0x00, 0x11}
	rb_1024 = []byte{0x08, 0x00, 0x43}
	rb_2048 = []byte{0x08, 0x60, 0x01}
)

var (
	errUnsupportedCipher = errors.New("cipher block size not supported")
	errInvalidTagSize    = errors.New("tags size must between 1 and the cipher's block size")
)

// XOR xors the bytes in dst with src and writes the result to dst.
// The destination is assumed to have enough space.
func XOR(dest, src []byte) {
	xor(dest, src)
}

// Sum computes the CMAC checksum with the given tagsize of msg using the cipher.Block.
func Sum(msg []byte, c cipher.Block, tagsize int) ([]byte, error) {
	h, err := NewWithTagSize(c, tagsize)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// Verify computes the CMAC checksum with the given tagsize of msg and compares
// it with the given mac. This functions returns true if and only if the given mac
// is equal to the computed one.
func Verify(mac, msg []byte, c cipher.Block, tagsize int) bool {
	sum, err := Sum(msg, c, tagsize)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(mac, sum) == 1
}

// New returns a hash.Hash computing the CMAC checksum.
func New(c cipher.Block) (hash.Hash, error) {
	return NewWithTagSize(c, c.BlockSize())
}

// NewWithTagSize returns a hash.Hash computing the CMAC checksum with the
// given tag size. The tag size must between the 1 and the cipher's block size.
func NewWithTagSize(c cipher.Block, tagsize int) (hash.Hash, error) {
	blocksize := c.BlockSize()

	if tagsize <= 0 || tagsize > blocksize {
		return nil, errInvalidTagSize
	}

	var p []byte
	switch blocksize << 3 {
	default:
		return nil, errUnsupportedCipher
	case 64:
		p = rb_64
	case 128:
		p = rb_128
	case 160:
		p = rb_160
	case 192:
		p = rb_192
	case 224:
		p = rb_224
	case 256:
		p = rb_256
	case 320:
		p = rb_320
	case 384:
		p = rb_384
	case 448:
		p = rb_448
	case 512:
		p = rb_512
	case 768:
		p = rb_768
	case 1024:
		p = rb_1024
	case 2048:
		p = rb_2048
	}

	m := &macFunc{
		cipher: c,
		k0:     make([]byte, blocksize),
		k1:     make([]byte, blocksize),
		buf:    make([]byte, blocksize),
	}
	m.tagsize = tagsize
	c.Encrypt(m.k0, m.k0)

	v := shift(m.k0, m.k0)
	mask := (-v) & 0xFF
	m.k0[blocksize-3] ^= p[0] & byte(mask)
	m.k0[blocksize-2] ^= p[1] & byte(mask)
	m.k0[blocksize-1] ^= p[2] & byte(mask)

	v = shift(m.k1, m.k0)
	mask = (-v) & 0xFF
	m.k1[blocksize-3] ^= p[0] & byte(mask)
	m.k1[blocksize-2] ^= p[1] & byte(mask)
	m.k1[blocksize-1] ^= p[2] & byte(mask)

	return m, nil
}

// The CMAC message auth. function
type macFunc struct {
	cipher  cipher.Block
	k0, k1  []byte
	buf     []byte
	off     int
	tagsize int
}

func (h *macFunc) Size() int { return h.cipher.BlockSize() }

func (h *macFunc) BlockSize() int { return h.cipher.BlockSize() }

func (h *macFunc) Reset() {
	copy(h.buf, zeros)
	h.off = 0
}

func (h *macFunc) Write(msg []byte) (int, error) {
	bs := h.BlockSize()
	n := len(msg)

	if h.off > 0 {
		dif := bs - h.off
		if n > dif {
			xor(h.buf[h.off:], msg[:dif])
			msg = msg[dif:]
			h.cipher.Encrypt(h.buf, h.buf)
			h.off = 0
		} else {
			xor(h.buf[h.off:], msg)
			h.off += n
			return n, nil
		}
	}

	if length := len(msg); length > bs {
		nn := length & (^(bs - 1))
		if length == nn {
			nn -= bs
		}
		for i := 0; i < nn; i += bs {
			xor(h.buf, msg[i:i+bs])
			h.cipher.Encrypt(h.buf, h.buf)
		}
		msg = msg[nn:]
	}

	if length := len(msg); length > 0 {
		xor(h.buf[h.off:], msg)
		h.off += length
	}

	return n, nil
}

func (h *macFunc) Sum(b []byte) []byte {
	blocksize := h.cipher.BlockSize()

	// Don't change the buffer so the
	// caller can keep writing and summing.
	hbuf := make([]byte, blocksize)

	if h.off < blocksize {
		copy(hbuf, h.k1)
	} else {
		copy(hbuf, h.k0)
	}

	xor(hbuf, h.buf)
	if h.off < blocksize {
		hbuf[h.off] ^= 0x80
	}

	h.cipher.Encrypt(hbuf, hbuf)
	return append(b, hbuf[:h.tagsize]...)
}

func shift(dst, src []byte) int {
	var b, bit byte
	for i := len(src) - 1; i >= 0; i-- { // a range would be nice
		bit = src[i] >> 7
		dst[i] = src[i]<<1 | b
		b = bit
	}
	return int(b)
}
