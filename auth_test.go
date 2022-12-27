package auth

import (
	"testing"
)

func TestAES(t *testing.T) {
	content := "这里是加密的内容"
	key := "12345678-ABC-DEF"

	util := NewAesUtil(key)

	encrypt, err := util.encrypt(content)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(encrypt)

	decrypt, err := util.decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(decrypt)

	if decrypt != content {
		t.Fatal()
	}

	_, err = util.decrypt("ok")
	if err != nil {
		t.Log(err)
	}

	_, err = util.decrypt("MIGMLzmBWVp3Py3X0QZUww==")
	if err != nil {
		t.Log(err)
	}
}
