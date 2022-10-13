package auth

import (
	"encoding/base64"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

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
	split := strings.Split(idAndSecret, "@")
	if len(split) != 2 {
		return "", "", &ClientTokenFailError{}
	}
	return split[0], split[1], nil
}

func GenerateClientToken(clientId string, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientId + "@" + clientSecret))
}
