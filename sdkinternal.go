// Package dlp sdkinternal.go implements internal API for DLP
package dlp

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/bytedance/godlp/detector"
	"github.com/bytedance/godlp/errlist"
	"github.com/bytedance/godlp/log"
	"github.com/bytedance/godlp/mask"
)

type HttpResponseBase struct {
	RetCode int    `json:"ret_code"`
	RetMsg  string `json:"ret_msg"`
}

type DescribeRulesResponse struct {
	HttpResponseBase
	Rule []byte `json:"rule,omitempty"`
	Crc  uint32 `json:"crc,omitempty"` // rule 的crc
}

// private func

// recoveryImplStatic implements recover if panic which is used for NewEngine API
func recoveryImplStatic() {
	if r := recover(); r != nil {
		if isCriticalPanic(r.(error)) {
			panic(r)
		} else {
			fmt.Fprintf(os.Stderr, "%s, msg: %+v\n", errlist.ERR_PANIC.Error(), r)
			debug.PrintStack()
		}
	}
}

// recoveryImpl implements recover if panic
func (I *Engine) recoveryImpl() {
	if r := recover(); r != nil {
		if isCriticalPanic(r.(error)) {
			panic(r)
		} else {
			fmt.Fprintf(os.Stderr, "%s, msg: %+v\n", errlist.ERR_PANIC.Error(), r)
			debug.PrintStack()
		}
	}
}

// isCriticalPanic checks wheterh error is critical error
func isCriticalPanic(r error) bool {
	isCritical := false
	switch r {
	case errlist.ERR_HAS_NOT_CONFIGED:
		isCritical = true
	default:
		isCritical = false
	}
	return isCritical
}

// hasClosed check whether the engine has been closed
func (I *Engine) hasClosed() bool {
	return I.isClosed
}

func (I *Engine) isOnlyForLog() bool {
	return I.isForLog
}

// hasConfiged check whether the engine has been configed
func (I *Engine) hasConfiged() bool {
	return I.isConfiged
}

// postLoadConfig will load config object
func (I *Engine) postLoadConfig() error {
	if I.confObj.Global.MaxLogInput > 0 {
		DEF_MAX_LOG_INPUT = I.confObj.Global.MaxLogInput
	}
	if I.confObj.Global.MaxRegexRuleID > 0 {
		DEF_MAX_REGEX_RULE_ID = I.confObj.Global.MaxRegexRuleID
	}
	I.initLogger()
	if err := I.loadDetector(); err != nil {
		return err
	}
	if err := I.loadMaskWorker(); err != nil {
		return err
	}
	I.isConfiged = true
	return nil
}

// isDebugMode checks if DLP is in debug mode
func (I *Engine) isDebugMode() bool {
	return strings.Compare(strings.ToLower(I.confObj.Global.Mode), "debug") == 0
}

// initLogger inits logger obj, in debug mode, log message will be printed in console and log file,
// in release mode, log level is ERROR and log message will be printed into stderr
func (I *Engine) initLogger() error {
	if I.isDebugMode() {
		// log.SetLevel(0)
		log.Debugf("DLP@%s run in debug mode", I.Version)
	} else { // release mode
		// log.SetLevel(log.LevelError)
	}
	return nil
}

// loadDetector loads detectors from config
func (I *Engine) loadDetector() error {
	// fill detectorMap
	I.fillDetectorMap()
	// disable rules
	return I.disableRulesImpl(I.confObj.Global.DisableRules)
}

// loadMaskWorker loads maskworker from config
func (I *Engine) loadMaskWorker() error {
	maskRuleList := I.confObj.MaskRules
	if I.maskerMap == nil {
		I.maskerMap = make(map[string]mask.MaskAPI)
	}
	for _, rule := range maskRuleList {
		if obj, err := mask.NewMaskWorker(rule, I); err == nil {
			ruleName := obj.GetRuleName()
			if old, ok := I.maskerMap[ruleName]; ok {
				log.Errorf("ruleName: %s, error: %s", old.GetRuleName(), errlist.ERR_LOADMASK_NAME_CONFLICT.Error())
			} else {
				I.maskerMap[ruleName] = obj
			}
		}
	}
	return nil
}

// dfsJSON walk a json object, used for DetectJSON and DeidentifyJSON
// in DetectJSON(), isDeidentify is false, kvMap is write only, will store json object path and value
// in DeidentifyJSON(), isDeidentify is true, kvMap is read only, will store path and MaskText of sensitive information
func (I *Engine) dfsJSON(path string, ptr *interface{}, kvMap map[string]string, isDeidentify bool) interface{} {
	path = strings.ToLower(path)
	switch (*ptr).(type) {
	case map[string]interface{}:
		for k, v := range (*ptr).(map[string]interface{}) {
			subpath := path + "/" + k
			(*ptr).(map[string]interface{})[k] = I.dfsJSON(subpath, &v, kvMap, isDeidentify)
		}
	case []interface{}:
		for i, v := range (*ptr).([]interface{}) {
			subpath := ""
			if len(path) == 0 {
				subpath = fmt.Sprintf("/[%d]", i)
			} else {
				subpath = fmt.Sprintf("%s[%d]", path, i)
			}
			(*ptr).([]interface{})[i] = I.dfsJSON(subpath, &v, kvMap, isDeidentify)
		}
	case string:
		var subObj interface{}
		if val, ok := (*ptr).(string); ok {
			// try nested json Unmarshal
			if I.maybeJSON(val) {
				if err := json.Unmarshal([]byte(val), &subObj); err == nil {
					obj := I.dfsJSON(path, &subObj, kvMap, isDeidentify)
					if ret, err := json.Marshal(obj); err == nil {
						retStr := string(ret)
						return retStr
					} else {
						return obj
					}
				}
			} else { // plain text
				if isDeidentify {
					if mask, ok := kvMap[path]; ok {
						return mask
					} else {
						return val
					}
				} else {
					kvMap[path] = val
					return val
				}
			}
		}
	case float64:
		// float64 don't need to mask
		if val, ok := (*ptr).(float64); ok {
			if isDeidentify {
				if mask, ok := kvMap[path]; ok {
					return mask
				} else {
					return val
				}
			}
			kvMap[path] = fmt.Sprintf("%0.f", val)
			return val
		}
	case bool:
		// bool don't need to mask
		if val, ok := (*ptr).(bool); ok {
			kvMap[path] = fmt.Sprint(val)
		}
	case nil:
		if path != "" {
			kvMap[path] = fmt.Sprint(nil)
		}
	}
	return *ptr
}

// maybeJSON check whether input string is a JSON object or array
func (I *Engine) maybeJSON(in string) bool {
	maybeObj := strings.IndexByte(in, '{') != -1 && strings.LastIndexByte(in, '}') != -1
	maybeArray := strings.IndexByte(in, '[') != -1 && strings.LastIndexByte(in, ']') != -1
	return maybeObj || maybeArray
}

// selectRulesForLog will select rules for log
func (I *Engine) selectRulesForLog() error {
	return nil
}

func (I *Engine) fillDetectorMap() error {
	ruleList := I.confObj.Rules
	if I.detectorMap == nil {
		I.detectorMap = make(map[int32]detector.DetectorAPI)
	}
	enableRules := I.confObj.Global.EnableRules
	fullSet := map[int32]bool{}
	for _, rule := range ruleList {
		if obj, err := detector.NewDetector(rule); err == nil {
			ruleID := obj.GetRuleID()
			I.detectorMap[ruleID] = obj
			fullSet[ruleID] = false
		} else {
			log.Errorf(err.Error())
		}
	}
	// if EnableRules is empty, all rules are loaded
	// else only some rules are enabled.
	if len(enableRules) > 0 {
		for _, ruleID := range enableRules {
			if _, ok := I.detectorMap[ruleID]; ok {
				fullSet[ruleID] = true
			}
		}
		for k, v := range fullSet {
			if !v {
				I.detectorMap[k] = nil
			}
		}
	}
	return nil
}

// disableRules will disable rules based on ruleList, pass them all
// 禁用规则，原子操作，每次禁用是独立操作，不会有历史依赖
func (I *Engine) applyDisableRules(ruleList []int32) {
	I.confObj.Global.DisableRules = ruleList
	I.loadDetector()
}

func (I *Engine) disableRulesImpl(ruleList []int32) error {
	for _, ruleID := range ruleList {
		if _, ok := I.detectorMap[ruleID]; ok {
			I.detectorMap[ruleID] = nil
		}
	}
	total := 0
	for k, rule := range I.detectorMap {
		if rule != nil {
			total++
		} else {
			delete(I.detectorMap, k)
		}
	}
	if I.isDebugMode() {
		log.Debugf("Total %d Rule loaded", total)
	}
	return nil
}
