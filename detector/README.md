# detector模块 实现说明

# DetectorAPI接口

1. GetRuleInfo() string
- GetRuleInfo returns rule as string

2. GetRuleID() int32
- GetRuleID returns RuleID

3. GetMaskRuleName() string
- GetMaskRuleName returns MaskRuleName

4. IsValue() bool
- IsValue checks whether RuleType is VALUE

5. IsKV() bool
- IsValue checks whether RuleType is KV

6. DetectBytes(inputBytes []byte) ([]*dlpheader.DetectResult, error)
- DetectBytes detects sensitive info for bytes

7. DetectMap(inputMap map[string]string) ([]*dlpheader.DetectResult, error)
- DetectMap detects sensitive info for map

8. Close()
- Close release detector object