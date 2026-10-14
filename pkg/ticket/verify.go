// Package ticket validates OpenV community-signed connection tickets.
// Server integrations must additionally enforce replay prevention and any
// applicable game ownership, entitlement, or platform checks.
package ticket

import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "strings"
 "time"
)

type Claims struct {
 Issuer string `json:"iss"`
 Subject string `json:"sub"`
 Audience string `json:"aud"`
 ID string `json:"jti"`
 Issued int64 `json:"iat"`
 Expires int64 `json:"exp"`
 Version int `json:"v"`
}

// Verify validates the signature and claims without making a network request.
// Replay resistance must be enforced by the caller with a persistent/shared
// atomic replay store keyed by ticket JTI and audience.
func Verify(encoded, audience string, key ed25519.PublicKey, now time.Time) (Claims,error) {
 var zero Claims
 if len(key)!=ed25519.PublicKeySize{return zero,errors.New("invalid verification key")}
 parts:=strings.Split(encoded,".")
 if len(parts)!=3||parts[0]!="ov1"{return zero,errors.New("invalid ticket format")}
 raw,e:=base64.RawURLEncoding.DecodeString(parts[1])
 if e!=nil||len(raw)==0||len(raw)>4096{return zero,errors.New("invalid payload")}
 sig,e:=base64.RawURLEncoding.DecodeString(parts[2])
 if e!=nil||len(sig)!=ed25519.SignatureSize||!ed25519.Verify(key,[]byte(parts[1]),sig){return zero,errors.New("invalid signature")}
 var c Claims
 if e=json.Unmarshal(raw,&c);e!=nil{return zero,errors.New("invalid claims")}
 unix:=now.Unix()
 if c.Version!=1||c.Issuer!="openv-community"||c.Subject==""||c.ID==""||audience==""||c.Audience!=audience||c.Issued>unix||c.Expires<=unix||c.Expires<=c.Issued||c.Expires-c.Issued>90{
  return zero,errors.New("invalid or expired claims")
 }
 return c,nil
}

// DecodePublicKey converts the /api/v1/keys public_key field to an Ed25519 key.
func DecodePublicKey(value string)(ed25519.PublicKey,error){
 b,e:=base64.RawURLEncoding.DecodeString(value)
 if e!=nil||len(b)!=ed25519.PublicKeySize{return nil,errors.New("invalid Ed25519 public key")}
 return ed25519.PublicKey(b),nil
}
