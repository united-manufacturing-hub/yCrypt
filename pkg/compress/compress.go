package compress

import (
	"github.com/klauspost/compress"
	"github.com/klauspost/compress/zstd"
)

var encoder, _ = zstd.NewWriter(nil)
var decoder, _ = zstd.NewReader(nil)

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

func ZstdDecompress(compressedData []byte) (data []byte, err error) {
	if compressedData[0] == 0 {
		return compressedData[1:], nil
	} else {
		return decoder.DecodeAll(compressedData[1:], make([]byte, 0, len(compressedData)))
	}
}
