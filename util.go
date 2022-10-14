package auth

import (
	"encoding/base64"
	"errors"
	"math/rand"
	"net/http"
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

func ParseClientToken(clientToken string) (clientId string, clientSecret string, err error) {
	output, err := base64.StdEncoding.DecodeString(clientToken)
	if err != nil {
		panic(err)
	}
	idAndSecret := string(output)
	split := strings.Split(idAndSecret, ClientIdAndSecretSplitter)
	if len(split) != 2 {
		return "", "", errors.New(MsgClientTokenFail)
	}
	return split[0], split[1], nil
}

func GenerateClientToken(clientId string, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientId + ClientIdAndSecretSplitter + clientSecret))
}

func ExtractCommonHeader(r *http.Request, header string) string {
	return r.Header.Get(header)
}

func ExtractUserToken(r *http.Request, header, headerSchema string) (string, error) {
	schemaAndToken := r.Header.Get(header)
	if len(schemaAndToken) == 0 || !strings.HasPrefix(schemaAndToken, headerSchema+" ") {
		return "", errors.New(MsgUserTokenEmpty)
	}
	return schemaAndToken[len(headerSchema)+1:], nil
}

func ExtractClientInfoAndToken(r *http.Request, header, headerSchema string) (clientId string, clientSecret string, schemaAndToken string, err error) {
	clientId = ""
	clientSecret = ""
	schemaAndToken = r.Header.Get(header)
	err = nil
	if len(schemaAndToken) == 0 || !strings.HasPrefix(schemaAndToken, headerSchema+" ") {
		err = errors.New(MsgClientTokenEmpty)
		return
	}
	clientId, clientSecret, err = ParseClientToken(schemaAndToken[len(headerSchema)+1:])
	return
}
