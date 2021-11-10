// Package conf provides configuration handler for dlp
package conf

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/bytedance/godlp/errlist"
	"gopkg.in/yaml.v2"
)

type MaskRuleItem struct {
	RuleName      string   `yaml:"RuleName"`
	MaskType      string   `yaml:"MaskType"` // one of [CHAR, TAG, REPLACE, EMPTY, ALGO ]
	Value         string   `yaml:"Value"`
	Offset        int32    `yaml:"Offset"`
	Padding       int32    `yaml:"Padding"`
	Length        int32    `yaml:"Length"`
	Reverse       bool     `yaml:"Reverse"`
	IgnoreCharSet string   `yaml:"IgnoreCharSet"`
	IgnoreKind    []string `yaml:"IgnoreKind"` // one of [NUMERIC, ALPHA_UPPER_CASE, ALPHA_LOWER_CASE, WHITESPACE, PUNCTUATION]
}

type RuleItem struct {
	RuleID      int32  `yaml:"RuleID"`
	InfoType    string `yaml:"InfoType"`
	Description string `yaml:"Description"`
	EnName      string `yaml:"EnName"`
	CnName      string `yaml:"CnName"`
	Level       string `yaml:"Level"` // L1 (least Sensitive) ~ L4 (Most Sensitive)
	// (KReg || KDict) && (VReg || VDict)
	Detect struct {
		KReg  []string `yaml:"KReg"`       // Regex List for Key
		KDict []string `yaml:"KDict,flow"` // Dict for Key
		VReg  []string `yaml:"VReg"`       // Regex List for Value
		VDict []string `yaml:"VDict,flow"` // Dict for Value
	} `yaml:"Detect"`
	// result which is hit by blacklist will not returned to caller
	Filter struct {
		// BReg || BDict
		BReg  []string `yaml:"BReg"`       // Regex List for BlackList
		BDict []string `yaml:"BDict,flow"` // Dict for BlackList
		BAlgo []string `yaml:"BAlgo"`      // Algorithm List for BlackList, one of [ MASKED ]
	} `yaml:"Filter"`
	// result need pass verify process before retured to caller
	Verify struct {
		// CReg || CDict
		CReg  []string `yaml:"CReg"`       // Regex List for Context Verification
		CDict []string `yaml:"CDict,flow"` // Dict for Context Verification
		VAlgo []string `yaml:"VAlgo"`      // Algorithm List for Verification, one of [ IDVerif , CardVefif ]
	} `yaml:"Verify"`
	Mask    string            `yaml:"Mask"` // MaskRuleItem.RuleName for Mask
	ExtInfo map[string]string `yaml:"ExtInfo"`
}

type DlpConf struct {
	Global struct {
		Date           string  `yaml:"Date"`
		ApiVersion     string  `yaml:"ApiVersion"`
		Mode           string  `yaml:"Mode"`
		AllowRPC       bool    `yaml:"AllowRPC"`
		EnableRules    []int32 `yaml:"EnableRules,flow"`
		DisableRules   []int32 `yaml:"DisableRules,flow"`
		MaxLogInput    int32   `yaml:"MaxLogInput"`
		MaxRegexRuleID int32   `yaml:"MaxRegexRuleID"`
	} `yaml:"Global"`
	MaskRules []MaskRuleItem `yaml:"MaskRules"`
	Rules     []RuleItem     `yaml:"Rules"`
}

// public func

// NewDlpConf creates DlpConf object by conf content string
func NewDlpConf(confString string) (*DlpConf, error) {
	return newDlpConfImpl(confString)
}

// NewDlpConfByPath creates DlpConf object by confPath
func NewDlpConfByPath(confPath string) (*DlpConf, error) {
	if len(confPath) == 0 {
		return nil, errlist.ERR_CONFPATH_EMPTY
	}
	if fileData, err := ioutil.ReadFile(confPath); err == nil {
		return newDlpConfImpl(string(fileData))
	} else {
		return nil, err
	}
}

var (
	defModeSet          []string = []string{"debug", "release"}
	defAPIVersionPrefix          = "v2"
	defMaskTypeSet      []string = []string{"CHAR", "TAG", "REPLACE", "ALGO"}
	defMaskAlgo         []string = []string{"BASE64", "MD5", "CRC32", "ADDRESS", "NUMBER", "DEIDENTIFY"}
	defIgnoreKind       []string = []string{"NUMERIC", "ALPHA_UPPER_CASE", "ALPHA_LOWER_CASE", "WHITESPACE", "PUNCTUATION"}
)

func (I *DlpConf) Verify() error {
	// Global

	// ApiVersion
	if !strings.HasPrefix(I.Global.ApiVersion, defAPIVersionPrefix) {
		return fmt.Errorf("%w, Global.APIVersion:%s failed", errlist.ERR_CONF_VERIFY_FAILED, I.Global.ApiVersion)
	}
	// Mode
	I.Global.Mode = strings.ToLower(I.Global.Mode)
	if inList(I.Global.Mode, defModeSet) == -1 { // not found
		return fmt.Errorf("%w, Global.Mode:%s failed", errlist.ERR_CONF_VERIFY_FAILED, I.Global.Mode)
	}
	// MaskRules
	for _, rule := range I.MaskRules {
		// MaskType
		if inList(rule.MaskType, defMaskTypeSet) == -1 {
			return fmt.Errorf("%w, Mask RuleName:%s, MaskType:%s is not suppored", errlist.ERR_CONF_VERIFY_FAILED, rule.RuleName, rule.MaskType)
		}
		if strings.Compare(rule.MaskType, "ALGO") == 0 {
			if inList(rule.Value, defMaskAlgo) == -1 {
				return fmt.Errorf("%w, Mask RuleName:%s, ALGO Value: %s is not supported", errlist.ERR_CONF_VERIFY_FAILED, rule.RuleName, rule.Value)
			}
		}
		if !(rule.Offset >= 0) {
			return fmt.Errorf("%w, Mask RuleName:%s, Offset: %d need >=0", errlist.ERR_CONF_VERIFY_FAILED, rule.RuleName, rule.Offset)
		}
		if !(rule.Length >= 0) {
			return fmt.Errorf("%w, Mask RuleName:%s, Length: %d need >=0", errlist.ERR_CONF_VERIFY_FAILED, rule.RuleName, rule.Length)
		}
		for _, kind := range rule.IgnoreKind {
			if inList(kind, defIgnoreKind) == -1 {
				return fmt.Errorf("%w, Mask RuleName:%s, IgnoreKind: %s is not supported", errlist.ERR_CONF_VERIFY_FAILED, rule.RuleName, kind)
			}
		}
	}
	// Rules
	for _, rule := range I.Rules {
		de := rule.Detect
		// at least one detect rule
		if len(de.KReg) == 0 && len(de.KDict) == 0 && len(de.VReg) == 0 && len(de.VDict) == 0 {
			return fmt.Errorf("%w, RuleID:%d, Detect field missing", errlist.ERR_CONF_VERIFY_FAILED, rule.RuleID)
		}
	}
	return nil
}

// private func

// newDlpConfImpl implements newDlpConf by receving conf content string
func newDlpConfImpl(confString string) (*DlpConf, error) {
	if len(confString) == 0 {
		return nil, errlist.ERR_CONF_EMPTY
	}
	confObj := new(DlpConf)
	if err := yaml.Unmarshal([]byte(confString), &confObj); err == nil {
		if err := confObj.Verify(); err == nil {
			return confObj, nil
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

// inList finds item in list
func inList(item string, list []string) int {
	for i, v := range list {
		if strings.Compare(item, v) == 0 { // found
			return i
		}
	}
	return -1 // not found
}
