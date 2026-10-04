package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Claims struct {
	Sub    string `json:"sub"`
	Tenant string `json:"tenant"`
	Role   string `json:"role"`
	Run    string `json:"run,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Lease  string `json:"lease,omitempty"`
	Iss    string `json:"iss"`
	Aud    string `json:"aud"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

var encoding = base64.RawURLEncoding

func sign(c Claims, key string) string {
	h := encoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	b, _ := json.Marshal(c)
	p := h + "." + encoding.EncodeToString(b)
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(p))
	return p + "." + encoding.EncodeToString(m.Sum(nil))
}
func verify(token, key string, now time.Time) (Claims, error) {
	var c Claims
	p := strings.Split(token, ".")
	bad := errors.New("invalid credentials")
	if len(p) != 3 {
		return c, bad
	}
	h, e := encoding.DecodeString(p[0])
	if e != nil {
		return c, bad
	}
	var header map[string]string
	if json.Unmarshal(h, &header) != nil || header["alg"] != "HS256" || header["typ"] != "JWT" {
		return c, bad
	}
	sig, e := encoding.DecodeString(p[2])
	if e != nil {
		return c, bad
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(p[0] + "." + p[1]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return c, bad
	}
	b, e := encoding.DecodeString(p[1])
	if e != nil || json.Unmarshal(b, &c) != nil {
		return c, bad
	}
	if c.Iss != "secureagent" || c.Aud != "gateway" || c.Exp <= now.Unix() || c.Iat > now.Unix()+5 || c.Sub == "" || c.Tenant == "" {
		return c, bad
	}
	if c.Role != "analyst" && c.Role != "approver" && c.Role != "worker" {
		return c, bad
	}
	if c.Role == "worker" && (c.Run == "" || c.Agent != "incident-response" || c.Lease == "") {
		return c, bad
	}
	return c, nil
}
