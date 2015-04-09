package brimcrypt

import (
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestBlockSizeForSize(t *testing.T) {
	for _, sizes := range [][]int64{
		{0, minBlockSize},
		{1, minBlockSize},
		{minBlockSize - 1, minBlockSize},
		{minBlockSize, minBlockSize},
		{160, 128},
		{161, 256},
		{209, 128},
		{2456, 256},
		{24567, 1024},
		{245678, 4096},
		{2456789, 16384},
		{24567890, 65536},
		{245678901, 65536},
		{3332545, 8192},
		{3339041, 65536},
		{3339889, 32768},
		{3370161, 16384},
		{3397889, 8192},
		{3404193, 65536},
	} {
		blockSize := blockSizeForSize(sizes[0])
		if blockSize != sizes[1] {
			t.Errorf("blockSizeForSize(%d) %d != %d", sizes[0], blockSize, sizes[1])
		}
	}
}

func TestCryptFile(t *testing.T) {
	tmpdir := EmptyTestDir(t)
	defer removeTestTree(tmpdir)
	tmp := path.Join(tmpdir, "test")
	key := []byte("0123456789abcdef0123456789abcdef")
	cf := NewCryptFile(tmp, key, 0)
	defer cf.Close()
	if cf.Path != tmp {
		t.Errorf("Path %s did not give %s", cf.Path, tmp)
		return
	}
	size, err := cf.Size()
	if err != nil {
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	} else {
		t.Errorf("Size did not give IsNotExist err; instead gave %d", size)
		return
	}
	in := `
        Rambling text for the testing of cryptfile. Should just generally test
        the functionality of cryptfile by ensuring we extend beyond just a
        single 128-byte block.
    `
	n, err := io.WriteString(cf, in)
	if err != nil {
		t.Fatal(err)
	}
	if n != len([]byte(in)) {
		t.Errorf("WriteString gave n %d != %d", n, len([]byte(in)))
		return
	}
	n64, err := cf.Seek(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n64 != 0 {
		t.Errorf("Seek gave n64 %d != 0", n64)
		return
	}
	size, err = cf.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len([]byte(in))) {
		t.Errorf("Size %d != %d", size, len([]byte(in)))
		return
	}
	if cf.blockSize != 128 {
		t.Errorf("blockSize %d != 128", cf.blockSize)
		return
	}
	out, err := ioutil.ReadAll(cf)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("output does not match input %#v != %#v", string(out), in)
		return
	}
	err = cf.Close()
	if err != nil {
		t.Fatal(err)
	}
	cf = NewCryptFile(tmp, key, 0)
	defer cf.Close()
	size, err = cf.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len([]byte(in))) {
		t.Errorf("Size %d != %d", size, len([]byte(in)))
		return
	}
	if cf.blockSize != 128 {
		t.Errorf("blockSize %d != 128", cf.blockSize)
		return
	}
	out, err = ioutil.ReadAll(cf)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("output does not match input %#v != %#v", string(out), in)
		return
	}
	half := int64(len([]byte(in)) / 2)
	n64, err = cf.Seek(half, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n64 != half {
		t.Errorf("Seek gave n64 %d != %d", n64, half)
		return
	}
	out, err = ioutil.ReadAll(cf)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in[half:] {
		t.Errorf("output does not match input %#v != %#v", string(out), in[half:])
		return
	}
	n64, err = cf.Seek(half, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n64 != half {
		t.Errorf("Seek gave n64 %d != %d", n64, half)
		return
	}
	n64, err = cf.Seek(-10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n64 != half-10 {
		t.Errorf("Seek gave n64 %d != %d", n64, half-10)
		return
	}
	out, err = ioutil.ReadAll(cf)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in[half-10:] {
		t.Errorf("output does not match input %#v != %#v", string(out), in[half-10:])
		return
	}
	n64, err = cf.Seek(-10, 2)
	if err != nil {
		t.Fatal(err)
	}
	exp64 := int64(len([]byte(in)) - 10)
	if n64 != exp64 {
		t.Errorf("Seek gave n64 %d != %d", n64, exp64)
		return
	}
	out, err = ioutil.ReadAll(cf)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in[exp64:] {
		t.Errorf("output does not match input %#v != %#v", string(out), in[exp64:])
		return
	}
	err = cf.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteEmpty(t *testing.T) {
	tmp := path.Join(os.TempDir(), "_Go_cryptfile_TestCryptFile")
	defer os.Remove(tmp)
	key := []byte("0123456789abcdef0123456789abcdef")
	cf := NewCryptFile(tmp, key, 0)
	defer cf.Close()
	err := cf.WriteAsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	size, err := cf.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Errorf("Size gave n %d != %d", size, 0)
		return
	}
	err = cf.Close()
	if err != nil {
		t.Fatal(err)
	}
	cf = NewCryptFile(tmp, key, 0)
	defer cf.Close()
	size, err = cf.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Errorf("Size gave n %d != %d", size, 0)
		return
	}
	out, err := ioutil.ReadAll(cf)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "" {
		t.Errorf("did not expect any output from ReadAll; got %#v", string(out))
		return
	}
	err = cf.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadWithoutPreviousOpen(t *testing.T) {
	tmpdir := EmptyTestDir(t)
	defer removeTestTree(tmpdir)
	tmp := path.Join(tmpdir, "test")
	key := []byte("0123456789abcdef0123456789abcdef")
	cf := NewCryptFile(tmp, key, 0)
	defer cf.Close()
	in := "Test Message"
	n, err := io.WriteString(cf, in)
	if err != nil {
		t.Fatal(err)
	}
	if n != len([]byte(in)) {
		t.Errorf("WriteString gave n %d != %d", n, len([]byte(in)))
		return
	}
	err = cf.Close()
	if err != nil {
		t.Fatal(err)
	}
	cf = NewCryptFile(tmp, key, 0)
	defer cf.Close()
	b := make([]byte, 13)
	n, err = cf.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(in) {
		t.Errorf("Read was supposed to give %d bytes, gave %d", len(in), n)
		return
	}
	if string(b[:n]) != in {
		t.Errorf("Read %#v != %#v", string(b[:n]), in)
	}
	err = cf.Close()
	if err != nil {
		t.Fatal(err)
	}
}
