# auth-go-sdk
[![Go Reference](https://pkg.go.dev/badge/github.com/Macrow/auth-go-sdk/v4.svg)](https://pkg.go.dev/github.com/Macrow/auth-go-sdk)

用于集成权限验证的开发包

## 快速开始

### 安装
```
go get -u github.com/Macrow/auth-go-sdk
```

### RSA
- 请使用```PKCS8```格式生成RSA秘钥对，长度至少为2048

### AES
- AES加密采用128位```AES/ECB/PKCS5Padding```，不使用偏移量，最后用Base64输出

### 客户端id要求
- 不能携带```@```符号
