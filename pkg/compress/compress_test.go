package compress

import (
	"bytes"
	"github.com/klauspost/compress"
	"github.com/klauspost/compress/zstd"
	"os"
	"path/filepath"
	"testing"
)

func TestCompressData(t *testing.T) {
	filesdata, err := getTestData()
	if err != nil {
		t.Fatal(err)
	}

	for _, data := range filesdata {
		t.Logf("Compressability of %s: %f", data.Name, compress.Estimate(data.Data))
		compressed := ZstdCompress(data.Data)
		t.Logf("Compressed data from %d to %d bytes", len(data.Data), len(compressed))
		t.Logf("Compression ratio: %f", float64(len(data.Data))/float64(len(compressed)))
		decompressed, err := ZstdDecompress(compressed)
		if err != nil {
			t.Fatalf("Failed to decompress data: %s (%v)", err, compressed)
		}
		if !bytes.Equal(decompressed, data.Data) {
			t.Fatalf("Decompressed data does not match original data (%v) != (%v)", decompressed, data)
		}
	}
}

type File struct {
	Name string
	Data []byte
}

func getTestData() (filedata []File, err error) {

	files, err := os.ReadDir("test_data")
	if err != nil {
		return filedata, err
	}
	filedata = make([]File, 0, len(files))

	for _, file := range files {
		var fd []byte
		fd, err = os.ReadFile(filepath.Join("test_data", file.Name()))
		if err != nil {
			return filedata, err
		}
		filedata = append(
			filedata, File{
				Name: file.Name(),
				Data: fd,
			})
	}
	return filedata, nil
}

func BenchmarkCompressSpeedFastest(b *testing.B) {
	filesdata, err := getTestData()
	if err != nil {
		b.Fatal(err)
	}
	var e, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range filesdata {
			zstdCompressT(data.Data, e)
		}
	}
}
func BenchmarkCompressSpeedDefault(b *testing.B) {
	filesdata, err := getTestData()
	if err != nil {
		b.Fatal(err)
	}
	var e, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range filesdata {
			zstdCompressT(data.Data, e)
		}
	}
}
func BenchmarkCompressSpeedBetterCompression(b *testing.B) {
	filesdata, err := getTestData()
	if err != nil {
		b.Fatal(err)
	}
	var e, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range filesdata {
			zstdCompressT(data.Data, e)
		}
	}
}
func BenchmarkCompressSpeedBestCompression(b *testing.B) {
	filesdata, err := getTestData()
	if err != nil {
		b.Fatal(err)
	}
	var e, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	var d, _ = zstd.NewReader(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range filesdata {
			bytesX := zstdCompressT(data.Data, e)
			var dataD []byte
			dataD, err = zstdDecompressT(bytesX, d)
			if err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(dataD, data.Data) {
				b.Fatalf("Decompressed data does not match original data (%v) != (%v)", dataD, data)
			}
		}
	}
}

func zstdCompressT(data []byte, enc *zstd.Encoder) []byte {
	if compress.Estimate(data) <= 0.1 {
		return append([]byte{0}, data...)
	}
	compressed := enc.EncodeAll(data, make([]byte, 0, len(data)))
	if len(compressed) >= len(data) {
		return append([]byte{0}, data...)
	} else {
		return append([]byte{1}, compressed...)
	}
}

func zstdDecompressT(compressedData []byte, dec *zstd.Decoder) (data []byte, err error) {
	if compressedData[0] == 0 {
		return compressedData[1:], nil
	} else {
		return dec.DecodeAll(compressedData[1:], make([]byte, 0, len(compressedData)))
	}
}
