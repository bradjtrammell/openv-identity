package main

import (
 "crypto/ed25519"
 "encoding/base64"
 "fmt"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "github.com/bradjtrammell/openv-identity/pkg/ticket"
)

func TestOnlineVerifierParity(t *testing.T) {
 s,err:=newService(filepath.Join(t.TempDir(),"identity.json"));if err!=nil{t.Fatal(err)}
 now:=time.Unix(1800000000,0);s.now=func()time.Time{return now}
 key:=s.signer.Public().(ed25519.PublicKey)
 base:=`"iss":"openv-community","sub":"player","aud":"server","jti":"id","iat":1800000000,"exp":1800000090,"v":1`
 tests:=[]struct{name,payload,audience string; accepted bool}{
  {"valid",`{`+base+`}`,"server",true},
  {"wrong audience",`{`+base+`}`,"other",false},
  {"duplicate subject",`{`+base+`,"sub":"admin"}`,"server",false},
  {"duplicate audience",`{`+base+`,"aud":"other"}`,"server",false},
  {"duplicate expiration",`{`+base+`,"exp":1800000200}`,"server",false},
  {"unknown privilege claim",`{`+base+`,"role":"admin"}`,"server",false},
  {"missing jti",`{`+strings.Replace(base,`,"jti":"id"`,"",1)+`}`,"server",false},
  {"string expiration",`{`+strings.Replace(base,`"exp":1800000090`,`"exp":"1800000090"`,1)+`}`,"server",false},
  {"expired",`{`+strings.Replace(base,`"exp":1800000090`,`"exp":1799999999`,1)+`}`,"server",false},
  {"future issue",`{`+strings.Replace(base,`"iat":1800000000`,`"iat":1800000001`,1)+`}`,"server",false},
  {"wrong issuer",`{`+strings.Replace(base,`"iss":"openv-community"`,`"iss":"attacker"`,1)+`}`,"server",false},
  {"trailing JSON",`{`+base+`} {}`,"server",false},
  {"empty audience parameter",`{`+base+`}`,"",false},
 }
 for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){
  encoded:=base64.RawURLEncoding.EncodeToString([]byte(tc.payload))
  signature:=base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.signer,[]byte(encoded)))
  signed:=fmt.Sprintf("ov1.%s.%s",encoded,signature)
  online,oe:=s.verifyTicket(signed,tc.audience)
  offline,fe:=ticket.Verify(signed,tc.audience,key,now)
  if (oe==nil)!=(fe==nil){t.Fatalf("online/offline mismatch: %v / %v",oe,fe)}
  if (oe==nil)!=tc.accept{t.Fatalf("accepted=%v, error=%v",oe==nil,oe)}
  if tc.accept&&(online!=offline||online.Subject!="player"){t.Fatalf("claims differ: online=%+v offline=%+v",online,offline)}
 })}
}

func TestRedeemRejectsAmbiguousSignedClaims(t *testing.T){
 s,err:=newService(filepath.Join(t.TempDir(),"identity.json"));if err!=nil{t.Fatal(err)}
 s.now=func()time.Time{return time.Unix(1800000000,0)}
 const serverID="server"
 const secret="test-server-secret"
 s.db.Servers[serverID]=Server{ID:serverID,Enabled:true,SecretHash:b64(sha256sum(secret))}
 sign:=func(payload string)string{
  encoded:=base64.RawURLEncoding.EncodeToString([]byte(payload))
  return "ov1."+encoded+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.signer,[]byte(encoded)))
 }
 invalid:=`{"iss":"openv-community","sub":"player","aud":"server","jti":"id","iat":1800000000,"exp":1800000090,"v":1,"sub":"admin"}`
 body:=map[string]string{"ticket":sign(invalid),"server_id":serverID,"server_secret":secret}
 api(t,s.handler(),"POST","/api/v1/tickets/redeem","",body,401)
 if len(s.db.Used)!=0{t.Fatal("rejected ticket poisoned replay store")}
 valid:=`{"iss":"openv-community","sub":"player","aud":"server","jti":"id","iat":1800000000,"exp":1800000090,"v":1}`
 body["ticket"]=sign(valid)
 api(t,s.handler(),"POST","/api/v1/tickets/redeem","",body,200)
 api(t,s.handler(),"POST","/api/v1/tickets/redeem","",body,409)
 if len(s.db.Used)!=1{t.Fatalf("expected one redeemed ticket, got %d",len(s.db.Used))}
}
