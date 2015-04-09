package brimcrypt

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
)

type CryptFile struct {
	Path              string
	key               []byte
	fallbackBlockSize int64
	unknownState      bool
	file              *os.File
	blockSize         int64
	size              int64
	headerDirty       bool
	plainBlockSize    int64
	plainBlock        []byte
	plainBlockIndex   int64
	plainBlockDirty   bool
	index             int64
}

// NewCryptFile returns a new CryptFile for the path using the 32 byte
// encryption key given. The estimated size is used to pick an optimal
// encrypted block size, but may be 0 if unknown.
func NewCryptFile(path string, key []byte, estimatedSize int64) *CryptFile {
	return &CryptFile{
		Path:              path,
		key:               key,
		fallbackBlockSize: blockSizeForSize(estimatedSize),
	}
}

type unusableError string

func (u unusableError) Error() string {
	return fmt.Sprintf("%#v is in an unusable state", u)
}

// Size returns the size of the decrypted data within the file.
func (cf *CryptFile) Size() (int64, error) {
	if cf.unknownState {
		return 0, unusableError(cf.Path)
	}
	if cf.file == nil {
		if err := cf.open(); err != nil {
			return 0, err
		}
	}
	return cf.size, nil
}

// See io.Reader
func (cf *CryptFile) Read(b []byte) (int, error) {
	if cf.unknownState {
		return 0, unusableError(cf.Path)
	}
	if cf.file == nil {
		if err := cf.open(); err != nil {
			return 0, err
		}
	}
	if cf.plainBlock == nil {
		if err := cf.read(); err != nil {
			return 0, err
		}
	}
	n := copy(b, cf.plainBlock[cf.plainBlockIndex:])
	cf.plainBlockIndex += int64(n)
	if cf.plainBlockIndex >= cf.plainBlockSize {
		if cf.plainBlockDirty {
			if err := cf.write(); err != nil {
				return n, err
			}
		}
		cf.plainBlock = nil
		cf.plainBlockIndex = 0
	}
	cf.index += int64(n)
	if cf.index > cf.size {
		n -= int(cf.index - cf.size)
		cf.index = cf.size
	}
	if n <= 0 {
		return n, io.EOF
	}
	return n, nil
}

// See io.Writer
func (cf *CryptFile) Write(b []byte) (int, error) {
	if cf.unknownState {
		return 0, unusableError(cf.Path)
	}
	if cf.file == nil {
		if err := cf.open(); err != nil {
			if !os.IsNotExist(err) {
				return 0, err
			}
			if err := cf.create(); err != nil {
				return 0, err
			}
		}
	}
	n := 0
	for len(b) > 0 {
		if cf.plainBlock == nil {
			if err := cf.read(); err != nil {
				if err == io.EOF {
					cf.plainBlock = make([]byte, cf.plainBlockSize)
					if _, err = rand.Read(cf.plainBlock); err != nil {
						cf.unknownState = true
						cf.file.Close()
						cf.file = nil
						return 0, err
					}
					cf.plainBlockIndex = 0
					cf.plainBlockDirty = false
				} else {
					return 0, err
				}
			}
		}
		n2 := copy(cf.plainBlock[cf.plainBlockIndex:], b)
		if n2 > 0 {
			cf.plainBlockDirty = true
			cf.plainBlockIndex += int64(n2)
			if cf.plainBlockIndex >= cf.plainBlockSize {
				if err := cf.write(); err != nil {
					return 0, err
				}
				cf.plainBlock = nil
				cf.plainBlockIndex = 0
				cf.plainBlockDirty = false
			}
			cf.index += int64(n2)
			cf.size = cf.index
			cf.headerDirty = true
		}
		n += n2
		b = b[n2:]
	}
	return n, nil
}

// WriteAsEmpty will write one encrypted data block but set the size in the
// header to 0. This makes it so an observer cannot tell the difference between
// a small single block file and a zero-byte file. Sometimes knowing a file is
// zero-bytes gives away information, so empty files should always use
// WriteAsEmpty.
func (cf *CryptFile) WriteAsEmpty() error {
	_, err := cf.Write([]byte{0})
	if err != nil {
		return err
	}
	cf.index = 0
	cf.size = 0
	cf.headerDirty = true
	return nil
}

// See io.Seeker
func (cf *CryptFile) Seek(offset int64, whence int) (int64, error) {
	if cf.unknownState {
		return 0, unusableError(cf.Path)
	}
	if cf.file == nil {
		if err := cf.open(); err != nil {
			return 0, err
		}
	}
	var newIndex int64
	switch whence {
	case 0:
		newIndex = offset
	case 1:
		newIndex = cf.index + offset
	case 2:
		newIndex = cf.size + offset
	default:
		return cf.index, fmt.Errorf("%#v invalid seek whence %d", cf.Path, whence)
	}
	if newIndex < 0 {
		return cf.index, fmt.Errorf("%#v invalid seek result %d", cf.Path, newIndex)
	}
	if newIndex/cf.plainBlockSize != cf.index/cf.plainBlockSize {
		if cf.plainBlockDirty {
			if err := cf.write(); err != nil {
				return cf.index, err
			}
		}
		cf.plainBlock = nil
	}
	cf.index = newIndex
	cf.plainBlockIndex = newIndex % cf.plainBlockSize
	return cf.index, nil
}

// See io.Closer
func (cf *CryptFile) Close() error {
	if !cf.unknownState {
		if cf.plainBlockDirty {
			if err := cf.write(); err != nil {
				return err
			}
		}
		if cf.headerDirty {
			if err := cf.writeHeader(); err != nil {
				return err
			}
		}
	}
	if cf.file != nil {
		cf.file.Close()
		cf.file = nil
	}
	cf.unknownState = false
	cf.blockSize = 0
	cf.size = 0
	cf.headerDirty = false
	cf.plainBlockSize = 0
	cf.plainBlock = nil
	cf.plainBlockIndex = 0
	cf.plainBlockDirty = false
	cf.index = 0
	return nil
}

// aes.BlockSize * 2
const header0ASize = 32

// int64
const header0BSize = 8

// header0ASize + hmacSize + aes.BlockSize[iv] + header0BSize, aligned to
// aes.BlockSize and then aligned to a power of 2
const minBlockSize = 128

func blockSizeForSize(size int64) int64 {
	if size <= minBlockSize {
		return minBlockSize
	}
	candidate := int64(65536)
	usable := candidate - hmacSize - aes.BlockSize
	best := candidate
	bestWaste := -1.0
	for candidate >= minBlockSize {
		waste := float64(((size+usable-1)/usable+1)*candidate-size) / float64(size)
		if bestWaste < 0 || bestWaste-waste > 0.01 {
			best = candidate
			bestWaste = waste
		}
		candidate >>= 1
		usable = candidate - hmacSize - aes.BlockSize
	}
	return best
}

func (cf *CryptFile) open() error {
	if cf.unknownState {
		return unusableError(cf.Path)
	}
	if cf.file != nil {
		return nil
	}
	file, err := os.OpenFile(cf.Path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	header := make([]byte, header0ASize)
	n, err := file.ReadAt(header, 0)
	if err != nil && (err != io.EOF || (err == io.EOF && n != len(header))) {
		file.Close()
		return err
	}
	if string(header[:11]) != "CRYPTFILE0 " {
		file.Close()
		return fmt.Errorf("%#v not CRYPTFILE0 data", cf.Path)
	}
	blockSize := int64(binary.BigEndian.Uint32(header[16:20]))
	if blockSize < minBlockSize {
		file.Close()
		return fmt.Errorf("%#v block size %d specified isn't at least %d", cf.Path, blockSize, minBlockSize)
	}
	if blockSize%aes.BlockSize != 0 {
		file.Close()
		return fmt.Errorf("%#v block size %d specified isn't a multiple of the AES block size %d", cf.Path, blockSize, aes.BlockSize)
	}
	enc := make([]byte, blockSize-header0ASize)
	n, err = file.ReadAt(enc, header0ASize)
	if err != nil && (err != io.EOF || (err == io.EOF && n != len(enc))) {
		file.Close()
		return err
	}
	dec, err := decrypt0(enc, cf.key)
	if err != nil {
		file.Close()
		return err
	}
	size := int64(binary.BigEndian.Uint64(dec[:8]))
	cf.file = file
	cf.blockSize = blockSize
	cf.plainBlockSize = blockSize - hmacSize - aes.BlockSize
	cf.size = size
	cf.headerDirty = false
	return nil
}

func (cf *CryptFile) create() error {
	cf.unknownState = false
	cf.blockSize = cf.fallbackBlockSize
	if cf.blockSize == 0 {
		cf.blockSize = minBlockSize
	}
	cf.size = 0
	cf.headerDirty = true
	cf.plainBlockSize = cf.blockSize - hmacSize - aes.BlockSize
	cf.plainBlock = nil
	cf.plainBlockIndex = 0
	cf.plainBlockDirty = false
	cf.index = 0
	dir := path.Dir(cf.Path)
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
	}
	cf.file, err = os.OpenFile(cf.Path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		cf.unknownState = true
		return err
	}
	return nil
}

func (cf *CryptFile) read() error {
	if cf.unknownState || cf.plainBlockSize == 0 {
		return unusableError(cf.Path)
	}
	enc := make([]byte, cf.blockSize)
	blockNumber := cf.index / cf.plainBlockSize
	n, err := cf.file.ReadAt(enc, cf.blockSize+blockNumber*cf.blockSize)
	if err != nil && (err != io.EOF || (err == io.EOF && int64(n) != cf.blockSize)) {
		if err != io.EOF {
			cf.unknownState = true
			cf.file.Close()
			cf.file = nil
		}
		return err
	}
	dec, err := decrypt0(enc, cf.key)
	if err != nil {
		return err
	}
	cf.plainBlock = dec
	cf.plainBlockDirty = false
	return nil
}

func (cf *CryptFile) write() error {
	if cf.unknownState {
		return unusableError(cf.Path)
	}
	enc, err := encrypt0(cf.plainBlock, cf.key)
	if err != nil {
		cf.unknownState = true
		cf.file.Close()
		cf.file = nil
		return err
	}
	blockNumber := cf.index / cf.plainBlockSize
	n, err := cf.file.WriteAt(enc, cf.blockSize+blockNumber*cf.blockSize)
	if err != nil && (err != io.EOF || (err == io.EOF && n != len(enc))) {
		if err != io.EOF {
			cf.unknownState = true
			cf.file.Close()
			cf.file = nil
		}
		return err
	}
	cf.plainBlockDirty = false
	return nil
}

func (cf *CryptFile) writeHeader() error {
	if cf.unknownState {
		return unusableError(cf.Path)
	}
	if cf.file == nil {
		return nil
	}
	header := make([]byte, header0ASize)
	copy(header, "CRYPTFILE0 ")
	binary.BigEndian.PutUint32(header[16:20], uint32(cf.blockSize))
	n, err := cf.file.WriteAt(header, 0)
	if err != nil && (err != io.EOF || (err == io.EOF && n != len(header))) {
		if err != io.EOF {
			cf.unknownState = true
			cf.file.Close()
			cf.file = nil
		}
		return err
	}
	dec := make([]byte, cf.plainBlockSize-header0ASize)
	binary.BigEndian.PutUint64(dec[:8], uint64(cf.size))
	_, err = rand.Read(dec[8:])
	if err != nil {
		cf.unknownState = true
		cf.file.Close()
		cf.file = nil
		return err
	}
	enc, err := encrypt0(dec, cf.key)
	if err != nil {
		cf.unknownState = true
		cf.file.Close()
		cf.file = nil
		return err
	}
	n, err = cf.file.WriteAt(enc, header0ASize)
	if err != nil && (err != io.EOF || (err == io.EOF && n != len(enc))) {
		if err != io.EOF {
			cf.unknownState = true
			cf.file.Close()
			cf.file = nil
		}
		return err
	}
	return nil
}
