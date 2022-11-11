package compress

import (
	"github.com/klauspost/compress"
	"github.com/klauspost/compress/zstd"
)

var encoder, _ = zstd.NewWriter(nil)
var decoder, _ = zstd.NewReader(nil)

// ZstdCompress compresses data using zstd compression.
// If the data is not compressible, it will be returned as is with a leading 0.
// If the data is compressible, it will be returned with a leading 1.
func ZstdCompress(data []byte) (compressedData []byte) {
	if compress.Estimate(data) <= 0.1 {
		return append([]byte{0}, data...)
	}
	compressed := encoder.EncodeAll(data, make([]byte, 0, len(data)))
	if len(compressed) >= len(data) {
		return append([]byte{0}, data...)
	} else {
		return append([]byte{1}, compressed...)
	}
}

// ZstdDecompress decompresses data using zstd compression.
// It strips the leading 0 or 1 and decompresses the data if necessary.
func ZstdDecompress(compressedData []byte) (data []byte, err error) {
	if compressedData[0] == 0 {
		return compressedData[1:], nil
	} else {
		return decoder.DecodeAll(compressedData[1:], make([]byte, 0, len(compressedData)))
	}
}
