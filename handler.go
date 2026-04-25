package CQUPT_CAS_SDK

import (
	"github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK/client"
	"github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK/encrypt"
)

func (r *SDK) Login(service string) (location string, err error) {
	// 初始化Http核心
	core, err := client.GetHttpSpyderCore(service)
	if err != nil {
		return "", err
	}

	// 获取全局Cookie
	err = core.GetGlobalCookie()
	if err != nil {
		return "", err
	}

	// 获取基础数据
	data, err := core.GetBasicData()
	if err != nil {
		return "", err
	}

	// 用盐加密密码
	encPasswd, err := encrypt.EncryptPasssword(r.Password, data.PwdEncryptSalt)
	if err != nil {
		return "", err
	}

	// 生成Login的POST表单数据
	body := core.GenLoginForm(r.UserName, encPasswd, data.Execution)

	// 执行登录流程
	loc, err := core.GetLocation(body)
	if err != nil {
		return "", err
	}

	return loc, nil
}
