package ticket

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "testing"
 "time"
)

func TestVerify(t *testing.T){
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 now:=time.Unix(1800000000,0)
 c:=Claims{Issuer:"openv-community",Subject:"player1",Audience:"server1",ID:"unique",Issued:now.Unix(),Expires:now.Add(90*time.Second).Unix(),Version:1}
 payload,e:=json.Marshal(c);if e!=nil{t.Fatal(e)}
 encoded:=base64.RawURLEncoding.EncodeToString(payload)
 signed:="ov1."+encoded+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv,[]byte(encoded)))
 got,e:=Verify(signed,"server1",pub,now);if e!=nil||got.Subject!="player1"{t.Fatalf("verification failed: %v",e)}
 if _,e=Verify(signed,"server2",pub,now);e==nil{t.Fatal("wrong audience accepted")}
 if _,e=Verify(signed,"server1",pub,now.Add(91*time.Second));e==nil{t.Fatal("expired ticket accepted")}
 if _,e=Verify(signed+"x","server1",pub,now);e==nil{t.Fatal("tampering accepted")}
 if _,e=DecodePublicKey(base64.RawURLEncoding.EncodeToString(pub));e!=nil{t.Fatal(e)}
}
