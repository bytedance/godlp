// Package dlp sdkdetect.go implements DLP detect APIs
package dlp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/godlp/detector"
	"github.com/bytedance/godlp/dlpheader"
	"github.com/bytedance/godlp/errlist"
)

// public func

// Detect find sensitive information for input string
// 对string进行敏感信息识别
func (I *Engine) Detect(inputText string) (retResults []*dlpheader.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfiged() { // not configed
		panic(errlist.ERR_HAS_NOT_CONFIGED)
	}
	if I.hasClosed() {
		return nil, errlist.ERR_PROCESS_AFTER_CLOSE
	}
	if len(inputText) > DEF_MAX_INPUT {
		return nil, fmt.Errorf("DEF_MAX_INPUT: %d , %w", DEF_MAX_INPUT, errlist.ERR_MAX_INPUT_LIMIT)
	}
	retResults, retErr = I.detectImpl(inputText)
	return
}

// DetectMap detects KV map
// 对map[string]string进行敏感信息识别
func (I *Engine) DetectMap(inputMap map[string]string) (retResults []*dlpheader.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfiged() { // not configed
		panic(errlist.ERR_HAS_NOT_CONFIGED)
	}
	if I.hasClosed() {
		return nil, errlist.ERR_PROCESS_AFTER_CLOSE
	}
	if len(inputMap) > DEF_MAX_ITEM {
		return nil, fmt.Errorf("DEF_MAX_ITEM: %d , %w", DEF_MAX_ITEM, errlist.ERR_MAX_INPUT_LIMIT)
	}
	inMap := make(map[string]string)
	for k, v := range inputMap {
		loK := strings.ToLower(k)
		inMap[loK] = v
	}
	retResults, retErr = I.detectMapImpl(inMap)
	return
}

// DetectJSON detects json string
// 对json string 进行敏感信息识别
func (I *Engine) DetectJSON(jsonText string) (retResults []*dlpheader.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfiged() { // not configed
		panic(errlist.ERR_HAS_NOT_CONFIGED)
	}
	if I.hasClosed() {
		return nil, errlist.ERR_PROCESS_AFTER_CLOSE
	}
	retResults, _, retErr = I.detectJSONImpl(jsonText)
	return
}

// private func

// detectImpl works for the Detect API
func (I *Engine) detectImpl(inputText string) ([]*dlpheader.DetectResult, error) {
	rd := bufio.NewReaderSize(strings.NewReader(inputText), DEF_LineBlockSize)
	currPos := 0
	results := make([]*dlpheader.DetectResult, 0, DEF_RESULT_SIZE)
	for {
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			line := I.detectPre(line)
			lineResults := I.detectProcess(line)
			postResutls := I.detectPost(lineResults, currPos)
			results = append(results, postResutls...)
			currPos += len(line)
		}
		if err != nil {
			if err != io.EOF {
				//show err
			}
			break
		}
	}
	return results, nil
}

// detectPre calls prepare func before detect
func (I *Engine) detectPre(line []byte) []byte {
	line = I.unquoteEscapeChar(line)
	line = I.replaceWideChar(line)
	return line
}

// detectProcess detects sensitive info for a line
func (I *Engine) detectProcess(line []byte) []*dlpheader.DetectResult {
	// detect from a byte array
	bytesResults, _ := I.detectBytes(line)
	// detect from a kvList which is extracted from the byte array
	// kvList is used for the two item with same key
	kvList := I.extractKVList(line)
	kvResults, _ := I.detectKVList(kvList)
	results := I.mergeResults(bytesResults, kvResults)
	return results
}

// detectBytes detects for a line
func (I *Engine) detectBytes(line []byte) ([]*dlpheader.DetectResult, error) {
	results := make([]*dlpheader.DetectResult, 0, DEF_RESULT_SIZE)
	var retErr error
	//start := time.Now()
	for _, obj := range I.detectorMap {
		if obj != nil && obj.IsValue() {
			if I.isOnlyForLog() { // used in log processor mod, need very efficient
				if obj.GetRuleID() > DEF_MAX_REGEX_RULE_ID && obj.UseRegex() { // if ID>MAX and rule uses regex
					continue // will not use this rule in log processor mod
				}
			}
			res, err := obj.DetectBytes(line)
			if err != nil {
				retErr = err
			}
			results = append(results, res...)
		}
	}
	//fmt.Printf("check rule:%d, len:%d, cast:%v\n", len(I.detectorMap), len(line), time.Since(start))

	// the last error will be returned
	return results, retErr
}

// extractKVList extracts KV item into a returned list
func (I *Engine) extractKVList(line []byte) []*detector.KVItem {
	kvList := make([]*detector.KVItem, 0, DEF_RESULT_SIZE)

	sz := len(line)
	for i := 0; i < sz; {
		// k:v k=v k:=v k==v, chinese big "："
		ch, width := utf8.DecodeRune(line[i:])
		if width == 0 { // error
			break
		}
		if i+1 < sz && isEqualChar(ch) {
			left := ""
			right := ""
			vPos := []int{-1, -1}
			kPos := []int{-1, -1}
			isFound := false
			if i+2 < sz {
				nx, nxWidth := utf8.DecodeRune(line[i+width:])
				if nx == '=' {
					left, kPos = lastToken(line, i)
					right, vPos = firstToken(line, i+width+nxWidth)
					isFound = true
				}
			}
			if !isFound {
				left, kPos = lastToken(line, i)
				right, vPos = firstToken(line, i+width)
				isFound = true
			}
			//log.Debugf("%s [%d,%d) = %s [%d,%d)", left, kPos[0], kPos[1], right, vPos[0], vPos[1])
			_ = kPos
			if len(left) != 0 && len(right) != 0 {
				loLeft := strings.ToLower(left)
				kvList = append(kvList, &detector.KVItem{
					Key:   loLeft,
					Value: right,
					Start: vPos[0],
					End:   vPos[1],
				})
			}
		}
		i += width
	}
	return kvList
}

// isEqualChar checks whether the r is = or : or :=
func isEqualChar(r rune) bool {
	return r == ':' || r == '=' || r == '：'
}

// firstToken extract the first token from bytes, returns token and position info
func firstToken(line []byte, offset int) (string, []int) {
	sz := len(line)
	if offset >= 0 && offset < sz {
		st := offset
		ed := sz
		// find first non cutter
		for i := offset; i < sz; i++ {
			if strings.IndexByte(DEF_CUTTER, line[i]) == -1 {
				st = i
				break
			}
		}
		// find first cutter
		for i := st + 1; i < sz; i++ {
			if strings.IndexByte(DEF_CUTTER, line[i]) != -1 {
				ed = i
				break
			}
		}
		return string(line[st:ed]), []int{st, ed}
	} else { // out of bound
		return "", nil
	}
}

// lastToken extract the last token from bytes, returns token and position info
func lastToken(line []byte, offset int) (string, []int) {
	sz := len(line)
	if offset >= 0 && offset < sz {
		st := 0
		ed := offset
		// find first non cutter
		for i := offset - 1; i >= 0; i-- {
			if strings.IndexByte(DEF_CUTTER, line[i]) == -1 {
				ed = i + 1
				break
			}
		}
		// find first cutter
		for i := ed - 1; i >= 0; i-- {
			if strings.IndexByte(DEF_CUTTER, line[i]) != -1 {
				st = i + 1
				break
			}
		}
		return string(line[st:ed]), []int{st, ed}
	} else {
		return "", nil
	}
}

// detectKVList accepts kvList to do detection
func (I *Engine) detectKVList(kvList []*detector.KVItem) ([]*dlpheader.DetectResult, error) {
	results := make([]*dlpheader.DetectResult, 0, DEF_RESULT_SIZE)

	for _, obj := range I.detectorMap {
		if obj != nil && obj.IsKV() {
			if I.isOnlyForLog() { // used in log processor mod, need very efficient
				if obj.GetRuleID() > DEF_MAX_REGEX_RULE_ID && obj.UseRegex() { // if ID>MAX and rule uses regex
					continue // will not use this rule in log processor mod
				}
			}
			// can not call I.DetectMap, because it will call mask, but position info has not been provided
			mapResults, _ := obj.DetectList(kvList)
			for i, _ := range mapResults {
				// detectKVList is called from detect(), so result type will be VALUE
				mapResults[i].ResultType = detector.RESULT_TYPE_VALUE
			}
			results = append(results, mapResults...)
		}
	}
	return results, nil
}

// detectPost calls post func after detect
func (I *Engine) detectPost(results []*dlpheader.DetectResult, currPos int) []*dlpheader.DetectResult {
	ret := I.ajustResultPos(results, currPos)
	ret = I.maskResults(ret)
	return ret
}

// Result type define is uesd for sort in mergeResults
type ResultList []*dlpheader.DetectResult

// Len function is used for sort in mergeResults
func (a ResultList) Len() int {
	return len(a)
}

// Swap function is used for sort in mergeResults
func (a ResultList) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Less function is used for sort in mergeResults
func (a ResultList) Less(i, j int) bool {
	if a[i].ByteStart < a[j].ByteStart {
		return true
	} else if a[i].ByteStart == a[j].ByteStart {
		if a[i].ByteEnd < a[j].ByteEnd {
			return true
		} else if a[i].ByteEnd == a[j].ByteEnd { // same
			return a[i].RuleID < a[j].RuleID
		} else {
			return false
		}
	} else {
		return false
	}
}

// Contain checks whether a[i] contains a[j]
func (a ResultList) Contain(i, j int) bool {
	return a[i].ByteStart <= a[j].ByteStart && a[j].ByteEnd <= a[i].ByteEnd
}

// Equal checks whether positions are equal
func (a ResultList) Equal(i, j int) bool {
	return a[i].ByteStart == a[j].ByteStart && a[j].ByteEnd == a[i].ByteEnd
}

// merge and sort two detect results
func (I *Engine) mergeResults(a []*dlpheader.DetectResult, b []*dlpheader.DetectResult) []*dlpheader.DetectResult {
	var total []*dlpheader.DetectResult
	if len(a) == 0 {
		total = b
	} else {
		if len(b) == 0 {
			total = a
		} else { // len(a)!=0 && len(b)!=0
			total = make([]*dlpheader.DetectResult, 0, len(a)+len(b))
			total = append(total, a...)
			total = append(total, b...)
		}
	}
	if len(total) == 0 { // nothing
		return total
	}
	// sort
	sort.Sort(ResultList(total))
	sz := len(total)
	mark := make([]bool, sz)
	// firstly, all elements will be left
	for i := 0; i < sz; i++ {
		mark[i] = true
	}
	for i := 0; i < sz; i++ {
		if mark[i] {
			for j := i + 1; j < sz; j++ {
				if mark[j] {
					// inner element will be ignored
					if ResultList(total).Equal(i, j) {
						mark[i] = false
						break
					} else {
						if ResultList(total).Contain(i, j) {
							mark[j] = false
						}
						if ResultList(total).Contain(j, i) {
							mark[i] = false
						}
					}
				}
			}
		}
	}
	ret := make([]*dlpheader.DetectResult, 0, sz)
	for i := 0; i < sz; i++ {
		if mark[i] {
			ret = append(ret, total[i])
		}
	}
	return ret
}

// ajustResultPos ajust position offset
func (I *Engine) ajustResultPos(results []*dlpheader.DetectResult, currPos int) []*dlpheader.DetectResult {
	if currPos > 0 {
		for i := range results {
			results[i].ByteStart += currPos
			results[i].ByteEnd += currPos
		}
	}
	return results
}

// maskResults fill result.MaskText by calling mask.MaskResult()
func (I *Engine) maskResults(results []*dlpheader.DetectResult) []*dlpheader.DetectResult {
	for _, res := range results {
		if detector, ok := I.detectorMap[res.RuleID]; ok {
			maskRuleName := detector.GetMaskRuleName()
			if maskWorker, ok := I.maskerMap[maskRuleName]; ok {
				maskWorker.MaskResult(res)
			} else { // Not Found
				//log.Errorf(fmt.Errorf("MaskRuleName: %s, Error: %w", maskRuleName, errlist.ERR_MASK_RULE_NOTFOUND).Error())
				res.MaskText = res.Text
			}
		}
	}
	return results
}

// detectMapImpl detect sensitive info for inputMap
func (I *Engine) detectMapImpl(inputMap map[string]string) ([]*dlpheader.DetectResult, error) {
	results := make([]*dlpheader.DetectResult, 0, DEF_RESULT_SIZE)
	for _, obj := range I.detectorMap {
		if obj != nil {
			res, err := obj.DetectMap(inputMap)
			if err != nil {
				//log.Errorf(err.Error())
			}
			results = append(results, res...)
		}
	}
	// merge result to reduce combined item
	results = I.mergeResults(results, nil)
	results = I.maskResults(results)

	return results, nil
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

// detectJSONImpl implements detectJSON
func (I *Engine) detectJSONImpl(jsonText string) (retResults []*dlpheader.DetectResult, kvMap map[string]string, retErr error) {
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(jsonText), &jsonObj); err == nil {
		//fmt.Printf("%+v\n", jsonObj)
		kvMap = make(map[string]string, 0)
		I.dfsJSON("", &jsonObj, kvMap, false)
		retResults, retErr = I.detectMapImpl(kvMap)
		for _, item := range retResults {
			if orig, ok := kvMap[item.Key]; ok {
				if out, err := I.deidentifyByResult(orig, []*dlpheader.DetectResult{item}); err == nil {
					kvMap[item.Key] = out
				}
			}
		}
		return
	} else {
		if e, ok := err.(*json.SyntaxError); ok {
			return nil, nil, fmt.Errorf("%s: offset[%d], str[%s]", err.Error(), e.Offset,
				jsonText[max(int(e.Offset)-4, 0):min(int(e.Offset+10), len(jsonText))])
		}
		return nil, nil, err
	}
}

// replaceWideChar replace wide char with one byte char
func (I *Engine) replaceWideChar(lineArray []byte) []byte {
	sz := len(lineArray)
	for i := 0; i < sz; {
		if (lineArray[i] & 0x80) != 0x80 { //ascii char
			i++
			continue
		}
		r, width := utf8.DecodeRune(lineArray[i:])
		if width == 0 { //error
			break
		}
		switch r {
		case '【':
			copy(lineArray[i:i+width], "  [")
		case '】':
			copy(lineArray[i:i+width], "]  ")
		case '：':
			copy(lineArray[i:i+width], "  :") // must use [space,space,:], for :=
		case '「':
			copy(lineArray[i:i+width], "  {")
		case '」':
			copy(lineArray[i:i+width], "}  ")
		case '（':
			copy(lineArray[i:i+width], "  (")
		case '）':
			copy(lineArray[i:i+width], ")  ")
		case '《':
			copy(lineArray[i:i+width], "  <")
		case '》':
			copy(lineArray[i:i+width], ">  ")
		case '。':
			copy(lineArray[i:i+width], ".  ")
		case '？':
			copy(lineArray[i:i+width], "?  ")
		case '！':
			copy(lineArray[i:i+width], "!  ")
		case '，':
			copy(lineArray[i:i+width], ",  ")
		case '、':
			copy(lineArray[i:i+width], ",  ")
		case '；':
			copy(lineArray[i:i+width], ";  ")

		}
		i += width
	}
	return lineArray
}

// unquoteEscapeChar replace escaped char with orignal char
func (I *Engine) unquoteEscapeChar(lineArray []byte) []byte {
	sz := len(lineArray)
	for i := 0; i < sz; {
		r := lineArray[i]
		if r == '\\' {
			// last 2 char
			if i+1 < sz {
				c := lineArray[i+1]
				value := byte(' ')
				switch c {
				case 'a':
					value = '\a'
				case 'b':
					value = '\b'
				case 'f':
					value = '\f'
				case 'n':
					value = '\n'
				case 'r':
					value = '\r'
				case 't':
					value = '\t'
				case 'v':
					value = '\v'
				case '\\':
					value = '\\'
				case '"':
					value = '"'
				case '\'':
					value = '\''
				}
				lineArray[i] = byte(' ') // space ch
				lineArray[i+1] = value
				i += 2
			} else {
				i++
			}
		} else {
			i++
		}
	}
	return lineArray
}
