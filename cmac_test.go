// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// A cipher.Block mock, simulating block ciphers
// with any block size.
type dummyCipher int

func (c dummyCipher) BlockSize() int { return int(c) }

func (c dummyCipher) Encrypt(dst, src []byte) { copy(dst, src) }

func (c dummyCipher) Decrypt(dst, src []byte) { copy(dst, src) }

func TestNew(t *testing.T) {
	var ciphers = []dummyCipher{8, 16, 20, 24, 28, 32, 40, 48, 56, 64, 96, 128, 256}
	for _, c := range ciphers {
		_, err := New(c)
		if err != nil {
			t.Fatalf("BlockSize: %d, Failed to create CMAC instance: %s", int(c), err)
		}
	}

	_, err := New(dummyCipher(21))
	if err == nil {
		t.Fatalf("CMAC allowed invalid block size: %d", 20)
	}
}

func TestNewWithTagSize(t *testing.T) {
	_, err := NewWithTagSize(dummyCipher(16), 0)
	if err == nil {
		t.Fatalf("NewWithTagSize allowed tag size: %d", 0)
	}
	_, err = NewWithTagSize(dummyCipher(16), 17)
	if err == nil {
		t.Fatalf("NewWithTagSize allowed tag size: %d", 17)
	}
}

func TestBlockSize(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Could not create CMAC instance: %s", err)
	}
	if bs := h.BlockSize(); bs != c.BlockSize() {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, c.BlockSize())
	}
}

func TestSize(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Could not create CMAC instance: %s", err)
	}
	if bs := h.Size(); bs != c.BlockSize() {
		t.Fatalf("Size() returned: %d - but expected: %d", bs, c.BlockSize())
	}
}

func TestReset(t *testing.T) {
	cipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(cipher)
	if err != nil {
		t.Fatalf("Failed to use CMAC with the specified cipher")
	}
	c, ok := h.(*macFunc)
	if !ok {
		t.Fatal("Impossible situation: New returns no CMAC struct")
	}
	orig := *c // copy

	c.Write(make([]byte, c.BlockSize()+1))
	c.Reset()

	if !bytes.Equal(c.buf, orig.buf) {
		t.Fatalf("Reseted buf field: %d - but expected: %d", c.buf, orig.buf)
	}
	if !bytes.Equal(c.k0, orig.k0) {
		t.Fatalf("Reseted k0 field: %d - but expected: %d", c.k0, orig.k0)
	}
	if !bytes.Equal(c.k1, orig.k1) {
		t.Fatalf("Reseted k1 field: %d - but expected: %d", c.k1, orig.k1)
	}
	if c.off != orig.off {
		t.Fatalf("Reseted off field: %d - but expected: %d", c.off, orig.off)
	}
	if c.cipher != orig.cipher {
		t.Fatalf("Reseted cipher field: %v - but expected: %v", c.cipher, orig.cipher)
	}
}

func TestWrite(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Failed to create CMAC instance: %s", err)
	}

	var msg1 []byte
	msg0 := make([]byte, 64)
	for i := range msg0 {
		h.Write(msg0[:i])
		msg1 = append(msg1, msg0[:i]...)
	}

	tag0 := h.Sum(nil)
	tag1, err := Sum(msg1, c, c.BlockSize())
	if err != nil {
		t.Fatalf("Failed to compute CMAC tag: %s", err)
	}

	if !bytes.Equal(tag0, tag1) {
		t.Fatalf("Sum differ from cmac.Sum\n Sum: %s \n cmac.Sum: %s", hex.EncodeToString(tag0), hex.EncodeToString(tag1))
	}
}

func TestSum(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}

	msg := make([]byte, 64)
	for i := range msg {
		h, err := New(c)
		if err != nil {
			t.Fatalf("Iteration %d: Failed to create CMAC instance: %s", i, err)
		}

		h.Write(msg[:i])
		tag0 := h.Sum(nil)

		tag1, err := Sum(msg[:i], c, c.BlockSize())
		if err != nil {
			t.Fatalf("Iteration %d: Failed to compute CMAC tag: %s", i, err)
		}

		if !bytes.Equal(tag0, tag1) {
			t.Fatalf("Iteration %d: Sum differ from cmac.Sum\n Sum: %s \n cmac.Sum %s", i, hex.EncodeToString(tag0), hex.EncodeToString(tag1))
		}
	}

	_, err = Sum(nil, dummyCipher(21), 21)
	if err == nil {
		t.Fatalf("cmac.Sum allowed invalid block size: %d", 21)
	}
}

func TestVerify(t *testing.T) {
	var mac [16]byte
	mac[0] = 128

	if Verify(mac[:], nil, dummyCipher(20), 20) {
		t.Fatalf("cmac.Verify allowed invalid block size: %d", 20)
	}
}

func TestCMACs(t *testing.T) {
	d := func(s string) []byte {
		b, _ := hex.DecodeString(s)
		return b
	}
	cmac := func(key []byte, data []byte) ([]byte, error) {
		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		h, err := New(c)
		if err != nil {
			return nil, err
		}
		h.Write(data)
		return h.Sum(nil), nil
	}
	tests := []struct{ key, value, mac []byte }{
		{d("5ACE7E50AB65D5D51FD5BF5A16B8205B"), d("C33C0001008004C767F2066180010000"), d("66DA61797E23DECA5D8ECA13BBADF7A9")},
		{d("5ACE7E50AB65D5D51FD5BF5A16B8205B"), d("3CC30001008004C767F2066180010000"), d("3A3E8110E05311F7A3FCF0D969BF2B48")},
		{d("3ED0920E5E6A0320D823D5987FEAFBB1"), d("434545394135334533453436334546314634353936333537333637333839363226636d61633d"), d("81EC45C175E72FF6FAC61BC7AB3BAEF6")},
	}

	for _, test := range tests {
		m, err := cmac(test.key, test.value)
		if err != nil {
			t.Fatalf("cmac(%X, %X): %v", test.key, test.value, err)
		}
		if !bytes.Equal(m, test.mac) {
			t.Fatalf("expected: %X, got: %X", test.mac, m)
		}
	}
}

// Benchmarks

func BenchmarkWrite_16B(b *testing.B) { benchmarkWrite(b, 16) }

func BenchmarkWrite_1K(b *testing.B) { benchmarkWrite(b, 1024) }

func BenchmarkWrite_64K(b *testing.B) { benchmarkWrite(b, 64*1024) }

func BenchmarkSum_16B(b *testing.B) { benchmarkSum(b, 16) }

func BenchmarkSum_1K(b *testing.B) { benchmarkSum(b, 1024) }

func BenchmarkSum_64K(b *testing.B) { benchmarkSum(b, 64*1024) }

func benchmarkWrite(b *testing.B, nBytes int) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		b.Fatalf("Failed to create CMAC instance: %s", err)
	}

	buf := make([]byte, nBytes)
	b.SetBytes(int64(nBytes))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func benchmarkSum(b *testing.B, nBytes int) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES instance: %s", err)
	}

	buf := make([]byte, nBytes)
	b.SetBytes(int64(nBytes))
	for i := 0; i < b.N; i++ {
		Sum(buf, c, c.BlockSize())
	}
}
