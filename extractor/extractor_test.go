package extractor

import "testing"

func TestExtractFormAction(t *testing.T) {
	cases := []struct {
		name   string
		html   string
		formID string
		want   string
	}{
		{
			name:   "标准 IDS 登录表单",
			html:   `<form id="pwdFromId" method="post" action="/authserver/login">`,
			formID: "pwdFromId",
			want:   "/authserver/login",
		},
		{
			name:   "action 在前 id 在后",
			html:   `<form action="/authserver/login" method="post" id="pwdFromId">`,
			formID: "pwdFromId",
			want:   "/authserver/login",
		},
		{
			name:   "单引号属性",
			html:   `<form id='pwdFromId' action='/authserver/login'>`,
			formID: "pwdFromId",
			want:   "/authserver/login",
		},
		{
			name:   "id 不匹配",
			html:   `<form id="other" action="/x">`,
			formID: "pwdFromId",
			want:   "",
		},
		{
			name:   "没有 action 属性",
			html:   `<form id="pwdFromId" method="post">`,
			formID: "pwdFromId",
			want:   "",
		},
		{
			name:   "多个 form 取匹配的那个",
			html:   `<form id="a" action="/a"></form><form id="pwdFromId" action="/login"></form>`,
			formID: "pwdFromId",
			want:   "/login",
		},
		{
			name:   "跨行属性",
			html:   "<form\n  id=\"pwdFromId\"\n  action=\"/authserver/login\"\n>",
			formID: "pwdFromId",
			want:   "/authserver/login",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractFormAction([]byte(c.html), c.formID)
			if got != c.want {
				t.Errorf("ExtractFormAction = %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractAnyFormAction(t *testing.T) {
	html := `<form id="casLoginForm" action="/cas/login"></form>`
	got := ExtractAnyFormAction([]byte(html), "pwdFromId", "casLoginForm")
	if got != "/cas/login" {
		t.Errorf("ExtractAnyFormAction = %q, want /cas/login", got)
	}

	got = ExtractAnyFormAction([]byte(html), "nope1", "nope2")
	if got != "" {
		t.Errorf("ExtractAnyFormAction = %q, want empty", got)
	}
}
