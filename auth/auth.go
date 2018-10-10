package auth

import ( 
  "fmt"
  "errors"
  "context"
  "bytes"
  "encoding/json"
  "encoding/base64"
  "crypto/aes"
  "crypto/cipher"
  "crypto/sha1"
  "net/http"
)

type Config struct {
  AppId string
  Secret string
}

type Client struct {
  appId string
  secret string
}

type User struct {
  OpenId string `json:"openId"`
  UinionId string `json:"unionId"`
  NickName string `json:"nickName"`
  AvatarUrl string `json:"avatarUrl"`
  Gender int `json:"gender"`
  Province string `json:"province"`
  City string `json:"city"`
  Country string `json:"country"`
}

type Credentials struct {
  Code string `json:"code"`
  RawData string `json:"rawData"`
  Signature string `json:"signature"`
  EncryptedData string `json:"encryptedData"`
  Iv string `json:"iv"`
}

func NewClient(ctx context.Context, conf *Config) (*Client, error) {
  return &Client{
    appId: conf.AppId,
    secret: conf.Secret,
  }, nil
}

type Session struct {
  OpenId string `json:"openid"`
  Key string `json:"session_key"`
  UinionId string `json:"uinionid"`
  ErrCode int `json:"errcode"`
  ErrMsg string `json:"errMsg"`
}

func (c *Client) GetSession(ctx context.Context, code string) (*Session, error) {
  r, err := http.Get("https://api.weixin.qq.com/sns/jscode2session" +
    "?appid=" + c.appId + "&secret=" + c.secret + 
    "&js_code=" + code + "&grant_type=authorization_code")

  if err != nil {
    return nil, err
  }

  session := Session{}
  err2 := json.NewDecoder(r.Body).Decode(&session)
  if err2 != nil {
    return nil, err2
  }

  if session.ErrCode > 0 {
    return nil, errors.New("wechat code2session: " + session.ErrMsg)
  }

  return &session, nil
}

func (c *Client) GetCurrentUser(ctx context.Context, creds *Credentials) (*User, error) {
  s, err := c.GetSession(ctx, creds.Code)
  if err != nil {
    return nil, err
  }

  // signature = sha1( rawData + session_key )
  sg := creds.RawData + s.Key
  sh := sha1.New() 
  sh.Write([]byte(sg))
  sgs := sh.Sum(nil)
  signature := fmt.Sprintf("%x", sgs)
  if creds.Signature != signature {
    return nil, errors.New("invalid signature")  
  }

  //
  key, _ := base64.StdEncoding.DecodeString(s.Key)
  iv, _ := base64.StdEncoding.DecodeString(creds.Iv)
  ciphertext, _ := base64.StdEncoding.DecodeString(creds.EncryptedData)

  block, err := aes.NewCipher(key)
	if err != nil {
    return nil, err
	}

  mode := cipher.NewCBCDecrypter(block, iv)
  mode.CryptBlocks(ciphertext, ciphertext)

  user := User{} 
  err2 := json.NewDecoder(bytes.NewReader(ciphertext)).Decode(&user)
  if err2 != nil {
    return nil, err2
  }

  return &user, nil
}



