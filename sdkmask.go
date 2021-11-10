// Package dlp sdkmask.go implements Mask API
package dlp

import (
	"fmt"
	"github.com/bytedance/godlp/dlpheader"
	"github.com/bytedance/godlp/errlist"
	"github.com/bytedance/godlp/mask"
	"reflect"
)

// public func

// Mask will return masked text directly based on methodName
func (I *Engine) Mask(inputText string, methodName string) (outputText string, err error) {
	defer I.recoveryImpl()
	if !I.hasConfiged() { // not configed
		panic(errlist.ERR_HAS_NOT_CONFIGED)
	}
	if I.hasClosed() {
		return "", errlist.ERR_PROCESS_AFTER_CLOSE
	}
	if len(inputText) > DEF_MAX_INPUT {
		return inputText, fmt.Errorf("DEF_MAX_INPUT: %d , %w", DEF_MAX_INPUT, errlist.ERR_MAX_INPUT_LIMIT)
	}
	if maskWorker, ok := I.maskerMap[methodName]; ok {
		return maskWorker.Mask(inputText)
	} else {
		return inputText, fmt.Errorf("methodName: %s, error: %w", methodName, errlist.ERR_MASKWORKER_NOTFOUND)
	}
}

// MaskStruct will mask a strcut object by tag mask info
// 根据tag mask里定义的脱敏规则对struct object直接脱敏, 会修改obj本身，传入指针，返回指针
func (I *Engine) MaskStruct(inPtr interface{}) (outPtr interface{}, retErr error) {
	outPtr = inPtr                          // fail back to inPtr
	retErr = errlist.ERR_MASK_STRUCT_OUTPUT // default return err if panic
	defer I.recoveryImpl()
	if !I.hasConfiged() { // not configed
		panic(errlist.ERR_HAS_NOT_CONFIGED)
	}
	if I.hasClosed() {
		return inPtr, errlist.ERR_PROCESS_AFTER_CLOSE
	}
	if inPtr == nil {
		return nil, errlist.ERR_MASK_STRUCT_INPUT
	}
	outPtr, retErr = I.maskStructImpl(inPtr, DEF_MAX_CALL_DEEP)
	return
}

// Register DIY Masker
// 注册自定义打码函数
func (I *Engine) RegisterMasker(maskName string, maskFunc func(string) (string, error)) error {
	defer I.recoveryImpl()
	if !I.hasConfiged() { // not configed
		panic(errlist.ERR_HAS_NOT_CONFIGED)
	}
	if I.hasClosed() {
		return errlist.ERR_PROCESS_AFTER_CLOSE
	}
	if _, ok := I.maskerMap[maskName]; ok {
		return errlist.ERR_MASKName_CONFLICT
	} else {
		if worker, err := I.NewDIYMaskWorker(maskName, maskFunc); err == nil {
			I.maskerMap[maskName] = worker
			return nil
		} else {
			return err
		}
	}
}

// private func

// DIYMaskWorker stores maskFuc and maskName
type DIYMaskWorker struct {
	maskFunc func(string) (string, error)
	maskName string
}

// GetRuleName is required by mask.MaskAPI
func (I *DIYMaskWorker) GetRuleName() string {
	return I.maskName
}

// Mask is required by mask.MaskAPI
func (I *DIYMaskWorker) Mask(in string) (string, error) {
	return I.maskFunc(in)
}

// MaskResult is required by mask.MaskAPI
func (I *DIYMaskWorker) MaskResult(res *dlpheader.DetectResult) error {
	if out, err := I.Mask(res.Text); err == nil {
		res.MaskText = out
		return nil
	} else {
		return err
	}
}

// NewDIYMaskWorker creates mask.MaskAPI object
func (I *Engine) NewDIYMaskWorker(maskName string, maskFunc func(string) (string, error)) (mask.MaskAPI, error) {
	worker := new(DIYMaskWorker)
	worker.maskName = maskName
	worker.maskFunc = maskFunc
	return worker, nil
}

// maskStructImpl will mask a strcut object by tag mask info
// 根据tag mask里定义的脱敏规则对struct object直接脱敏, 会修改obj本身，传入指针，返回指针
func (I *Engine) maskStructImpl(inPtr interface{}, level int) (interface{}, error) {
	//log.Errorf("[DLP] level:%d, maskStructImpl: %+v", level, inPtr)
	if level <= 0 { // call deep check
		//log.Errorf("[DLP] !call deep loop detected!")
		//log.Errorf("obj: %+v", inPtr)
		return inPtr, nil
	}
	valPtr := reflect.ValueOf(inPtr)
	if valPtr.Kind() != reflect.Ptr || valPtr.IsNil() || !valPtr.IsValid() || valPtr.IsZero() {
		return inPtr, errlist.ERR_MASK_STRUCT_INPUT
	}
	val := reflect.Indirect(valPtr)
	var retErr error
	if val.CanSet() {
		if val.Kind() == reflect.Struct {
			sz := val.NumField()
			if sz > DEF_MAX_INPUT {
				return inPtr, fmt.Errorf("DEF_MAX_INPUT: %d , %w", DEF_MAX_INPUT, errlist.ERR_MAX_INPUT_LIMIT)
			}
			for i := 0; i < sz; i++ {
				valField := val.Field(i)
				typeField := val.Type().Field(i)
				inStr := valField.String()
				outStr := inStr // default is orignal str
				methodName, ok := typeField.Tag.Lookup("mask")
				if !ok { // mask tag not found
					continue
				}
				if valField.CanSet() {
					switch valField.Kind() {
					case reflect.String:
						if len(methodName) > 0 {
							if maskWorker, ok := I.maskerMap[methodName]; ok {
								if masked, err := maskWorker.Mask(inStr); err == nil {
									outStr = masked
									valField.SetString(outStr)
								}
							}
						}
					case reflect.Struct:
						if valField.CanAddr() {
							//log.Errorf("[DLP] Struct, %s", typeField.Name)
							_, retErr = I.maskStructImpl(valField.Addr().Interface(), level-1)
						}
					case reflect.Ptr:
						if !valField.IsNil() {
							//log.Errorf("[DLP] Ptr, %s", typeField.Name)
							_, retErr = I.maskStructImpl(valField.Interface(), level-1)
						}
					case reflect.Interface:
						if valField.CanInterface() {
							valInterFace := valField.Interface()
							if inStr, ok := valInterFace.(string); ok {
								outStr := inStr
								if len(methodName) > 0 {
									if maskWorker, ok := I.maskerMap[methodName]; ok {
										if masked, err := maskWorker.Mask(inStr); err == nil {
											outStr = masked
											if valField.CanSet() {
												valField.Set(reflect.ValueOf(outStr))
											}
										}
									}
								}
							}
						}
					case reflect.Slice, reflect.Array:
						length := valField.Len()
						for i := 0; i < length; i++ {
							item := valField.Index(i)
							if item.Kind() == reflect.String {
								inStr := item.String()
								outStr := inStr
								// use parent mask info
								if len(methodName) > 0 {
									if maskWorker, ok := I.maskerMap[methodName]; ok {
										if masked, err := maskWorker.Mask(inStr); err == nil {
											outStr = masked
											if item.CanSet() {
												item.SetString(outStr)
											}
										}
									}
								}
							} else if item.Kind() == reflect.Ptr {
								if !item.IsNil() {
									//log.Errorf("[DLP] Ptr, %s", item.Type().Name())
									_, retErr = I.maskStructImpl(item.Interface(), level-1)
								}
							} else if item.Kind() == reflect.Struct {
								if item.CanAddr() {
									//log.Errorf("[DLP] Struct, %s", item.Type().Name())
									_, retErr = I.maskStructImpl(item.Addr().Interface(), level-1)
								}
							}
						}
					}
				}
			}
		}
	}
	return inPtr, retErr
}
