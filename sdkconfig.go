// Package dlp sdkconfig.go implement config related API
package dlp

import (
	"github.com/bytedance/godlp/conf"
)

// public func

// ApplyConfig by configuration content
// 传入conf string 进行配置
func (I *Engine) ApplyConfig(confString string) error {
	defer I.recoveryImpl()
	if confObj, err := conf.NewDlpConf(confString); err == nil {
		return I.applyConfigImpl(confObj)
	} else {
		return err
	}
}

// ApplyConfigFile by config file path
// 传入filePath 进行配置
func (I *Engine) ApplyConfigFile(filePath string) error {
	defer I.recoveryImpl()
	var retErr error
	if confObj, err := conf.NewDlpConfByPath(filePath); err == nil {
		retErr = I.applyConfigImpl(confObj)
	} else {
		retErr = err
	}
	return retErr
}


func (I *Engine) ApplyConfigDefault() error {
	return I.loadDefCfg()
}

// private func

// applyConfigImpl sets confObj into Engine, then postLoadConfig(), such as load Detector and MaskWorker
func (I *Engine) applyConfigImpl(confObj *conf.DlpConf) error {
	I.confObj = confObj
	return I.postLoadConfig()
}
