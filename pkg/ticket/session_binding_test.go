package ticket

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "strings"
    "testing"
    "time"
)

func TestV2SignedSessionClaimsAreExactAndVersionBound(t *testing.T) {
    public,private,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil { t.Fatal(err) }
    now:=time.Unix(1800000000,0)
    sid:=base64.RawURLEncoding.EncodeToString(make([]byte,32))
    sign:=func(version string,payload string)string{
        encoded:=base64.RawURLEncoding.EncodeToString([]byte(payload))
        return version+"."+encoded+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,[]byte(encoded)))
    }
    base:=`"iss":"openv-community","sub":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090`
    valid:=`{`+base+ `,"v":2,"sid":"`+sid+`"}`
    tests:=[]struct{name,version,payload string;accept bool}{
        {"valid ov2","ov2",valid,true},
        {"v2 missing sid","ov2",`{`+base+`,"v":2}`,false},
        {"v2 sid empty","ov2",`{`+base+`,"v":2,"sid":""}`,false},
        {"v2 sid malformed","ov2",`{`+base+`,"v":2,"sid":"invalid"}`,false},
        {"v2 duplicate sid","ov2",strings.TrimSuffix(valid,"}")+`,"sid":"`+sid+`"}`,false},
        {"v2 unknown claim","ov2",strings.TrimSuffix(valid,"}")+`,"admin":true}`,false},
        {"v1 cannot claim v2","ov1",valid,false},
        {"v2 cannot claim v1","ov2",`{`+base+`,"v":1}`,false},
        {"v1 cannot include sid","ov1",`{`+base+`,"v":1,"sid":"`+sid+`"}`,false},
        {"v1 still accepted","ov1",`{`+base+`,"v":1}`,true},
    }
    for _,tc:=range tests { t.Run(tc.name,func(t *testing.T){
        got,err:=Verify(sign(tc.version,tc.payload),"server",public,now)
        if tc.accept {
            if err!=nil { t.Fatalf("valid ticket rejected: %v",err) }
            if tc.version=="ov2" && (got.Version!=2||got.Session!=sid) { t.Fatalf("lost v2 binding: %+v",got) }
        } else if err==nil { t.Fatalf("invalid ticket accepted: %+v",got) }
    })}
}
