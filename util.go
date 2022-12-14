package auth

import (
	"encoding/base64"
	"github.com/go-logr/logr"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func GetNonEmptyValue(val string) string {
	if len(val) == 0 {
		panic("val is empty")
	}
	return val
}

func GetNonEmptyValueWithBackup(val string, backup string) string {
	if len(val) > 0 {
		return val
	}
	if len(backup) == 0 {
		panic("backup is empty")
	}
	return backup
}

func GenerateRandomKey() string {
	rand.Seed(time.Now().UnixNano())
	output := ""
	for i := 0; i < 6; i++ {
		output += strconv.Itoa(rand.Intn(10))
	}
	return output
}

func ParseClientToken(clientToken string, encryptContent bool, aesUtil *AesUtil, logger logr.Logger) (clientId string, clientSecret string, err error) {
	var idAndSecret string
	if encryptContent && aesUtil != nil {
		idAndSecret, err = aesUtil.decrypt(clientToken)
		if err != nil {
			logger.Error(err, err.Error())
			return "", "", ErrDecryptFail
		}
	} else {
		bytes, err := base64.StdEncoding.DecodeString(clientToken)
		if err != nil {
			panic(err)
		}
		idAndSecret = string(bytes)
	}
	split := strings.Split(idAndSecret, ClientIdAndSecretSplitter)
	if len(split) != 2 {
		return "", "", ErrClientTokenFail
	}
	return split[0], split[1], nil
}

func GenerateClientToken(clientId string, clientSecret string, aesUtil *AesUtil) (string, error) {
	if aesUtil == nil {
		return base64.StdEncoding.EncodeToString([]byte(clientId + ClientIdAndSecretSplitter + clientSecret)), nil
	} else {
		return aesUtil.encrypt(clientId + ClientIdAndSecretSplitter + clientSecret)
	}
}

func ExtractAccessCode(f GetHeaderFun, header string, encryptContent bool, aesUtil *AesUtil, logger logr.Logger) (string, error) {
	val := f(header)
	if len(val) == 0 {
		return "", ErrAccessCodeEmpty
	}
	if encryptContent && aesUtil != nil {
		var err error
		val, err = aesUtil.decrypt(val)
		if err != nil {
			logger.Error(err, err.Error())
			return "", ErrDecryptFail
		}
	}
	return val, nil
}

func ExtractRandomKey(f GetHeaderFun, header string) (string, error) {
	val := f(header)
	if len(val) == 0 {
		return "", ErrRandomKeyEmpty
	}
	return val, nil
}

func ExtractUserToken(fun GetHeaderFun, header, headerSchema string) (string, error) {
	schemaAndToken := fun(header)
	if len(schemaAndToken) == 0 || !strings.HasPrefix(schemaAndToken, headerSchema+" ") {
		return "", ErrUserTokenEmpty
	}
	return schemaAndToken[len(headerSchema)+1:], nil
}

func ExtractClientInfoAndToken(f GetHeaderFun, header, headerSchema string, encryptContent bool, aesUtil *AesUtil, logger logr.Logger) (clientId string, clientSecret string, schemaAndToken string, err error) {
	clientId = ""
	clientSecret = ""
	schemaAndToken = f(header)
	err = nil
	if len(schemaAndToken) == 0 || !strings.HasPrefix(schemaAndToken, headerSchema+" ") {
		err = ErrClientTokenEmpty
		return
	}
	clientId, clientSecret, err = ParseClientToken(schemaAndToken[len(headerSchema)+1:], encryptContent, aesUtil, logger)
	return
}

type SetValFunc = func(key string, val interface{})
type GetValFunc = func(Key string) interface{}

func SetSkipAuthCheck(skip bool, f SetValFunc) {
	f(KeySkipAuthCheck, skip)
}

func GetSkipAuthCheck(f GetValFunc) bool {
	v := f(KeySkipAuthCheck)
	if v == nil {
		return false
	}
	return v.(bool)
}

func SetJwtUser(jwtUser *JwtUser, f SetValFunc) {
	f(KeyJwtUser, jwtUser)
}

func GetJwtUser(f GetValFunc) *JwtUser {
	v := f(KeyJwtUser)
	if v == nil {
		return nil
	}
	return v.(*JwtUser)
}

func SetCustomAuth(customAuth interface{}, f SetValFunc) {
	f(KeyCustomAuth, customAuth)
}

func GetCustomAuth(f GetValFunc) interface{} {
	v := f(KeyCustomAuth)
	if v == nil {
		return nil
	}
	return v
}

func SetCustomPerm(customAuth interface{}, f SetValFunc) {
	f(KeyCustomPerm, customAuth)
}

func GetCustomPerm(f GetValFunc) interface{} {
	v := f(KeyCustomPerm)
	if v == nil {
		return nil
	}
	return v
}

func SetClientId(clientId string, f SetValFunc) {
	f(KeyClientId, clientId)
}

func GetClientId(f GetValFunc) interface{} {
	v := f(KeyClientId)
	if v == nil {
		return nil
	}
	return v.(string)
}

func SetMetaBy(metaBy string, f SetValFunc) {
	f(KeyMetaBy, metaBy)
}

func GetMetaBy(f GetValFunc) string {
	v := f(KeyMetaBy)
	if v == nil {
		return ""
	}
	return v.(string)
}
