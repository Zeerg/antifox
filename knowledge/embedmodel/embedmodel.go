// Package embedmodel vendors the potion-base-8M static embedding model
// (MinishLab, MIT — see LICENSE) so semantic search needs no external
// embeddings endpoint. It is a model2vec StaticModel: BERT WordPiece
// tokenization → embedding-table lookup → mean pool → L2 normalize.
// The weights are stored as little-endian IEEE-754 half floats; the vocab is
// the bge-base-en-v1.5 WordPiece vocabulary (do_lower_case, strip accents,
// handle_chinese_chars).
package embedmodel

import (
	_ "embed"
	"fmt"
	"math"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// ModelName is the identifier stored alongside embedded chunks so vectors are
// only compared against same-model rows.
const ModelName = "potion-base-8M"

// Dim is the embedding width produced by the vendored model.
const Dim = 256

// maxSeqLen bounds tokens per input (matching the encoder's practical context;
// knowledge chunks are a few hundred chars, far below this).
const maxSeqLen = 512

// maxWordLen mirrors BertTokenizer: words longer than this map to [UNK].
const maxWordLen = 100

//go:embed weights.f16.bin
var weightsBin []byte

//go:embed vocab.txt
var vocabTxt string

var (
	loadOnce  sync.Once
	loadErr   error
	weights   []uint16 // [vocabSize*Dim] little-endian fp16
	vocab     map[string]int32
	idCLS     int32
	idSEP     int32
	idUNK     int32
	vocabSize int
)

// Embed returns one L2-normalized Dim-length vector per input text, in order.
// Everything runs in-process: no network, no native libraries.
func Embed(texts []string) ([][]float32, error) {
	loadOnce.Do(func() { loadErr = load() })
	if loadErr != nil {
		return nil, loadErr
	}
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = embedOne(t)
	}
	return out, nil
}

func load() error {
	want := len(weightsBin)
	if want%(Dim*2) != 0 {
		return fmt.Errorf("embedmodel: weights size %d not a multiple of dim*2", want)
	}
	vocabSize = want / (Dim * 2)
	weights = make([]uint16, vocabSize*Dim)
	for i := range weights {
		weights[i] = uint16(weightsBin[2*i]) | uint16(weightsBin[2*i+1])<<8
	}
	vocab = make(map[string]int32, vocabSize)
	var id int32
	for _, tok := range strings.Split(vocabTxt, "\n") {
		if tok = strings.TrimSuffix(tok, "\r"); tok != "" {
			vocab[tok] = id
			id++
		}
	}
	if id != int32(vocabSize) {
		return fmt.Errorf("embedmodel: vocab has %d tokens but weights have %d rows", id, vocabSize)
	}
	var ok bool
	if idCLS, ok = vocab["[CLS]"]; !ok {
		return fmt.Errorf("embedmodel: vocab missing [CLS]")
	}
	if idSEP, ok = vocab["[SEP]"]; !ok {
		return fmt.Errorf("embedmodel: vocab missing [SEP]")
	}
	if idUNK, ok = vocab["[UNK]"]; !ok {
		return fmt.Errorf("embedmodel: vocab missing [UNK]")
	}
	return nil
}

func embedOne(text string) []float32 {
	ids := encode(text)
	acc := make([]float32, Dim)
	for _, id := range ids {
		base := int(id) * Dim
		for d := 0; d < Dim; d++ {
			acc[d] += f16to32(weights[base+d])
		}
	}
	inv := 1 / float32(len(ids))
	var normSq float64
	for d := range acc {
		acc[d] *= inv
		normSq += float64(acc[d]) * float64(acc[d])
	}
	if normSq > 0 {
		s := float32(1 / math.Sqrt(normSq))
		for d := range acc {
			acc[d] *= s
		}
	}
	return acc
}

// encode applies the BertTokenizer pipeline: BertNormalizer (clean control
// chars, space around CJK, lowercase, strip accents) → BertPreTokenizer
// (split on whitespace and punctuation) → WordPiece → [CLS] … [SEP].
func encode(text string) []int32 {
	var normd strings.Builder
	normd.Grow(len(text))
	for _, r := range text {
		switch {
		case r == 0 || r == 0xFFFD || unicode.Is(unicode.Cc, r):
			continue // clean_text: drop control chars + replacement char
		case unicode.Is(unicode.Zs, r) || r == '\t' || r == '\n' || r == '\r':
			normd.WriteByte(' ')
		case isCJK(r):
			normd.WriteByte(' ')
			normd.WriteRune(r)
			normd.WriteByte(' ')
		default:
			normd.WriteRune(r)
		}
	}
	cleaned := normd.String()
	// lowercase + strip accents (strip_accents defaults to do_lower_case=true):
	// NFD-decompose, drop non-spacing marks, lowercase.
	cleaned, _, err := transform.String(transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC), cleaned)
	if err != nil {
		cleaned = ""
	}
	cleaned = strings.ToLower(cleaned)

	// BertPreTokenizer: whitespace split, then isolate punctuation chars.
	var words []string
	for _, w := range strings.Fields(cleaned) {
		var cur strings.Builder
		flush := func() {
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		}
		for _, r := range w {
			if isPunct(r) {
				flush()
				words = append(words, string(r))
			} else {
				cur.WriteRune(r)
			}
		}
		flush()
	}

	// WordPiece greedy longest-match with "##" continuations.
	toks := make([]int32, 0, len(words)*2+2)
	toks = append(toks, idCLS)
	for _, w := range words {
		if len(toks) >= maxSeqLen-1 {
			break
		}
		runes := []rune(w)
		if utf8.RuneCountInString(w) > maxWordLen {
			toks = append(toks, idUNK)
			continue
		}
		start := 0
		for start < len(runes) {
			end := len(runes)
			var cur string
			for start < end {
				sub := string(runes[start:end])
				if start > 0 {
					sub = "##" + sub
				}
				if _, ok := vocab[sub]; ok {
					cur = sub
					break
				}
				end--
			}
			if cur == "" {
				toks = append(toks, idUNK)
				break
			}
			toks = append(toks, vocab[cur])
			start = end
		}
	}
	toks = append(toks, idSEP)
	return toks
}

func isCJK(r rune) bool {
	// HF BertTokenizer CJK ranges.
	return (r >= 0x4E00 && r <= 0x9FFF) ||
		(r >= 0x3400 && r <= 0x4DBF) ||
		(r >= 0x20000 && r <= 0x2A6DF) ||
		(r >= 0x2A700 && r <= 0x2B73F) ||
		(r >= 0x2B740 && r <= 0x2B81F) ||
		(r >= 0x2B820 && r <= 0x2CEAF) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0x2F800 && r <= 0x2FA1F)
}

func isPunct(r rune) bool {
	// ASCII punctuation ranges or Unicode punctuation category.
	if (r >= 33 && r <= 47) || (r >= 58 && r <= 64) || (r >= 91 && r <= 96) || (r >= 123 && r <= 126) {
		return true
	}
	return unicode.IsPunct(r)
}

// f16to32 converts an IEEE-754 binary16 to float32.
func f16to32(h uint16) float32 {
	s := uint32(h&0x8000) << 16
	e := uint32(h>>10) & 0x1F
	m := uint32(h) & 0x3FF
	var f uint32
	switch {
	case e == 0:
		// subnormal half → normal float
		if m == 0 {
			f = s
		} else {
			e = 1
			for m&0x400 == 0 {
				m <<= 1
				e--
			}
			m &= 0x3FF
			f = s | (e+112)<<23 | m<<13
		}
	case e == 0x1F:
		f = s | 0x7F800000 | m<<13 // inf/nan
	default:
		f = s | (e+112)<<23 | m<<13
	}
	return math.Float32frombits(f)
}
