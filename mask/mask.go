// Package mask implements Mask API
package mask

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/godlp/conf"
	"github.com/bytedance/godlp/dlpheader"
	"github.com/bytedance/godlp/errlist"
)

const (
	MASKTYPE_CHAR    = "CHAR"    // 用字符替换敏感信息，需要用到后面更详细的配置项。
	MASKTYPE_TAG     = "TAG"     // 用识别和处理规则中的InfoType, 以`<InfoType>`的形式替换敏感信息。
	MASKTYPE_REPLACE = "REPLACE" //用Value定义的字符串，替换敏感信息，可以设定为空串，用于直接抹除。
	MASKTYPE_ALGO    = "ALGO"    //用Value定义的算法函数，处理敏感信息，用算法返回值替换原文，目前支持的算法有 [BASE64, MD5, CRC32]

	MASK_ALGO_BASE64 = "BASE64"
	MASK_ALGO_MD5    = "MD5"
	MASK_ALGO_CRC32  = "CRC32"

	MASK_UNKNOWN_TAG = "UNKNOWN"
)

type MaskWorker struct {
	rule   conf.MaskRuleItem
	parent dlpheader.EngineAPI
}

type MaskAPI interface {
	// GetRuleName return RuleName of a MaskWorker
	// 返回RuleName
	GetRuleName() string
	// Mask will return masked string
	// 返回打码后的文本
	Mask(string) (string, error)
	// MaskResult will modify DetectResult.MaskText
	// 修改DetectResult.MaskText
	MaskResult(*dlpheader.DetectResult) error
}

// public func

// NewMaskWorker create MaskWorker based on MaskRule
func NewMaskWorker(rule conf.MaskRuleItem, p dlpheader.EngineAPI) (MaskAPI, error) {
	obj := new(MaskWorker)
	//IgnoreKind
	for _, kind := range rule.IgnoreKind {
		switch kind {
		case "NUMERIC":
			rule.IgnoreCharSet += "0123456789"
		case "ALPHA_LOWER_CASE":
			rule.IgnoreCharSet += "abcdefghijklmnopqrstuvwxyz"
		case "ALPHA_UPPER_CASE":
			rule.IgnoreCharSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		case "WHITESPACE":
			rule.IgnoreCharSet += " \t\n\x0B\f\r"
		case "PUNCTUATION":
			rule.IgnoreCharSet += "!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"
		}
	}
	obj.rule = rule
	obj.parent = p
	return obj, nil
}

// GetRuleName return RuleName of a MaskWorker
// 返回RuleName
func (I *MaskWorker) GetRuleName() string {
	return I.rule.RuleName
}

// MaskResult will modify DetectResult.MaskText
// 修改DetectResult.MaskText
func (I *MaskWorker) MaskResult(res *dlpheader.DetectResult) error {
	var err error
	if strings.Compare(I.rule.MaskType, MASKTYPE_TAG) == 0 {
		res.MaskText, err = I.maskTagImpl(res.Text, res.InfoType)
	} else {
		res.MaskText, err = I.Mask(res.Text)
	}
	return err
}

// Mask will return masked string
// 返回打码后的文本
func (I *MaskWorker) Mask(in string) (string, error) {
	out := in
	err := fmt.Errorf("RuleName: %s, MaskType: %s , %w", I.rule.RuleName, I.rule.MaskType, errlist.ERR_MASK_NOT_SUPPORT)
	switch I.rule.MaskType {
	case MASKTYPE_CHAR:
		out, err = I.maskCharImpl(in)
	case MASKTYPE_TAG:
		out, err = I.maskStrTagImpl(in)
	case MASKTYPE_REPLACE:
		out, err = I.maskReplaceImpl(in)
	case MASKTYPE_ALGO:
		out, err = I.maskAlgoImpl(in)
	}
	return out, err
}

// private func

const (
	// base64
	enterListRes = "6KGX6YGTfOi3r3zooZd86YeMfOadkXzplYd85bGvfOe7hAo="
	midListRes   = "56S+5Yy6fOWwj+WMunzlpKfljqZ85bm/5Zy6fOWPt+alvHzljZXlhYN85Y+3fOWxgnzlrqR85oi3Cg=="
)

var (
	enterList = make([]string, 0, 0)
	midList   = make([]string, 0, 0)
)

func init() {
	enterList = loadResList(enterListRes)
	midList = loadResList(midListRes)
}

// loadResList accepts base64 string, then convert them to string list
func loadResList(res string) []string {
	retList := make([]string, 0, 0)
	if decode, err := base64.StdEncoding.DecodeString(res); err == nil {
		trim := strings.TrimSpace(string(decode))
		retList = strings.Split(trim, "|")
	}
	return retList
}

// maskCharImpl mask in string with char
func (I *MaskWorker) maskCharImpl(in string) (string, error) {
	ch := byte('*') // default
	if len(I.rule.Value) > 0 {
		ch = I.rule.Value[0]
	}
	sz := len(in)
	out := []byte(in)
	if !I.rule.Reverse {
		cnt := 0
		st := 0
		if I.rule.Offset >= 0 {
			st = int(I.rule.Offset)
		}
		ed := sz
		if I.rule.Padding >= 0 {
			ed = sz - int(I.rule.Padding)
		}
		for i := st; i < ed; i++ {
			// if Length == 0 , do not check
			if I.rule.Length > 0 && cnt >= int(I.rule.Length) {
				break
			}
			if strings.IndexByte(I.rule.IgnoreCharSet, out[i]) == -1 { // ignore check
				out[i] = ch
			}
			cnt++
		}
	} else {
		cnt := 0
		ed := sz
		if I.rule.Offset >= 0 {
			ed = sz - 1 - int(I.rule.Offset)
		}
		st := 0
		if I.rule.Padding >= 0 {
			st = int(I.rule.Padding)
		}
		for i := ed; i >= st; i-- {
			if I.rule.Length > 0 && cnt >= int(I.rule.Length) {
				break
			}
			if strings.IndexByte(I.rule.IgnoreCharSet, out[i]) == -1 { // ignore check
				out[i] = ch
			}
			cnt++
		}
	}
	return string(out), nil
}

// maskTagImpl mask with the tag of in string
func (I *MaskWorker) maskTagImpl(in string, infoType string) (string, error) {
	return fmt.Sprintf("<%s>", infoType), nil
}

// maskReplaceImpl replace with rule.Value
func (I *MaskWorker) maskReplaceImpl(in string) (string, error) {
	return I.rule.Value, nil
}

// maskStrTagImpl first Deidentify to get infotype, then mask with infotype
func (I *MaskWorker) maskStrTagImpl(in string) (string, error) {
	if results, err := I.parent.Detect(in); err == nil {
		if len(results) > 0 {
			res := results[0]
			return I.maskTagImpl(in, res.InfoType)
		}
	}
	return I.maskTagImpl(in, MASK_UNKNOWN_TAG)
}

// maskAlgoImpl replace with algo(in)
func (I *MaskWorker) maskAlgoImpl(in string) (string, error) {
	inBytes := []byte(in)
	switch I.rule.Value {
	case "BASE64":
		return base64.StdEncoding.EncodeToString(inBytes), nil
	case "MD5":
		return fmt.Sprintf("%x", md5.Sum(inBytes)), nil
	case "CRC32":
		return fmt.Sprintf("%08x", crc32.ChecksumIEEE(inBytes)), nil
	case "ADDRESS":
		return I.maskAddressImpl(in)
	case "NUMBER":
		return I.maskNumberImpl(in)
	case "DEIDENTIFY":
		return I.maskDeidentifyImpl(in)
	default:
		return in, fmt.Errorf("RuleName: %s, MaskType: %s , Value:%s, %w", I.rule.RuleName, I.rule.MaskType, I.rule.Value, errlist.ERR_MASK_NOT_SUPPORT)
	}
}

// maskAddressImpl masks Address
func (I *MaskWorker) maskAddressImpl(in string) (string, error) {
	st := 0

	if pos, id := I.indexSubList(in, st, enterList, true); pos != -1 { // found
		st = pos + len(enterList[id])
	}
	out := in[:st]
	sz := len(in)
	for pos, id := I.indexSubList(in, st, midList, false); pos != -1 && st < sz; pos, id = I.indexSubList(in, st, midList, false) {
		out += strings.Repeat("*", pos-st)
		out += midList[id]
		st = pos + len(midList[id])
	}
	out += in[st:]
	out, _ = I.maskNumberImpl(out)
	if strings.Compare(in, out) == 0 { // mask Last 3 rune
		lastByteSz := 0
		for totalRune := 3; totalRune > 0 && len(out) > 0; totalRune-- {
			_, width := utf8.DecodeLastRuneInString(out)
			lastByteSz += width
			out = out[0 : len(out)-width]
		}
		out += strings.Repeat("*", lastByteSz)
	}
	return out, nil
}

// IndexSubList find index of a list of sub strings from a string
func (I *MaskWorker) indexSubList(in string, st int, list []string, isLast bool) (int, int) {
	tmp := in[st:]
	retPos := -1
	retId := -1
	for i, word := range list {
		if pos := strings.Index(tmp, word); pos != -1 { // found
			loc := st + pos
			if retPos == -1 { // first
				retPos = loc
				retId = i
				if !isLast { // not last return directly
					return retPos, retId
				}
			} else {
				if isLast {
					if loc >= retPos {
						retPos = loc
						retId = i
					}
				}
			}

		}
	}
	return retPos, retId
}

// maskNumberImpl will mask all number in the string
func (I *MaskWorker) maskNumberImpl(in string) (string, error) {
	outBytes := []byte(in)
	for i, ch := range outBytes {
		if ch >= '0' && ch <= '9' {
			outBytes[i] = '*'
		}
	}
	return string(outBytes), nil
}

func (I *MaskWorker) maskDeidentifyImpl(in string) (string, error) {
	out, _, err := I.parent.Deidentify(in)
	return out, err
}
