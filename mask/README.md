# mask模块 实现说明

mask模块负责脱敏打码的实现，任何脱敏的实现都需要实现MaskAPI接口，其中包括如下三个函数。

# MaskAPI接口

1. GetRuleName() string

- GetRuleName return RuleName of a MaskWorker
- 返回RuleName

2. Mask(string) (string, error)

- Mask will return masked string
- 返回打码后的文本
	
3. MaskResult(*dlpheader.DetectResult) error

- MaskResult will modify DetectResult.MaskText
- 修改DetectResult.MaskText

# MaskWoker类型

有两种MaskWorker：

1. MaskWorker

通过读取配置文件中MaskRule实现

2. DIYMaskWorker

调用方通过EngineAPI.RegisterMasker 传入自定义打码函数进行实现。


	