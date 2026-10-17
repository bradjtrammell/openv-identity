package ticket

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "testing"
    "time"
)

func TestStrictSignedV1Claims(t *testing.T) {
    public, private, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    now := time.Unix(1800000000, 0)
    sign := func(payload string) string {
        encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
        return "ov1." + encoded + "." +
            base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(encoded)))
    }
    base := `{"iss":"openv-community","sub":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090,"v":1}`
    tests := []struct {
        name string
        payload string
        accepted bool
    }{
        {"canonical issuer payload", base, true},
        {"reordered fields", `{"v":1,"exp":1800000090,"iat":1800000000,"jti":"nonce","aud":"server","sub":"player","iss":"openv-community"}`, true},
        {"duplicate subject", `{"iss":"openv-community","sub":"other","sub":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090,"v":1}`, false},
        {"case-variant duplicate", `{"iss":"openv-community","sub":"other","SUB":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090,"v":1}`, false},
        {"unicode-escaped duplicate", `{"iss":"openv-community","sub":"other","s\u0075b":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090,"v":1}`, false},
        {"unknown signed claim", `{"iss":"openv-community","sub":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090,"v":1,"role":"admin"}`, false},
        {"missing nonce", `{"iss":"openv-community","sub":"player","aud":"server","iat":1800000000,"exp":1800000090,"v":1}`, false},
        {"missing version", `{"iss":"openv-community","sub":"player","aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090}`, false},
        {"wrong claim type", `{"iss":"openv-community","sub":42,"aud":"server","jti":"nonce","iat":1800000000,"exp":1800000090,"v":1}`, false},
        {"trailing object", base + `{}`, false},
        {"array not object", `[]`, false},
        {"null claims", `null`, false},
        {"invalid JSON", `{"iss":`, false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            claims, err := Verify(sign(tt.payload), "server", public, now)
            if tt.accepted && (err != nil || claims.Subject != "player") {
                t.Fatalf("valid signed ticket rejected: claims=%+v error=%v", claims, err)
            }
            if !tt.accepted && err == nil {
                t.Fatalf("ambiguous or malformed signed ticket accepted: %+v", claims)
            }
        })
    }
}
