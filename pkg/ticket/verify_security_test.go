package ticket

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "strings"
    "testing"
    "time"
)

func TestTicketValidationBoundaries(t *testing.T) {
    public, private, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    now := time.Unix(1800000000, 0)
    valid := Claims{Issuer: "openv-community", Subject: "subject", Audience: "server", ID: "nonce", Issued: now.Unix(), Expires: now.Add(90 * time.Second).Unix(), Version: 1}
    sign := func(c Claims) string {
        t.Helper()
        payload, err := json.Marshal(c)
        if err != nil { t.Fatal(err) }
        encoded := base64.RawURLEncoding.EncodeToString(payload)
        return "ov1." + encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(encoded)))
    }
    cases := []struct {
        name string
        change func(*Claims)
    }{
        {"wrong issuer", func(c *Claims) { c.Issuer = "other" }},
        {"empty subject", func(c *Claims) { c.Subject = "" }},
        {"empty nonce", func(c *Claims) { c.ID = "" }},
        {"wrong audience", func(c *Claims) { c.Audience = "other" }},
        {"future issued", func(c *Claims) { c.Issued++ }},
        {"expired at boundary", func(c *Claims) { c.Expires = now.Unix() }},
        {"zero lifetime", func(c *Claims) { c.Expires = c.Issued }},
        {"overlong lifetime", func(c *Claims) { c.Expires++ }},
        {"wrong version", func(c *Claims) { c.Version = 2 }},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            claims := valid
            tc.change(&claims)
            if _, err := Verify(sign(claims), "server", public, now); err == nil {
                t.Fatal("invalid signed ticket accepted")
            }
        })
    }
    t.Run("exact lifetime allowed", func(t *testing.T) {
        if _, err := Verify(sign(valid), "server", public, now); err != nil { t.Fatal(err) }
    })
    t.Run("empty expected audience rejected", func(t *testing.T) {
        if _, err := Verify(sign(valid), "", public, now); err == nil { t.Fatal("empty audience accepted") }
    })
    t.Run("wrong public key rejected", func(t *testing.T) {
        other, _, err := ed25519.GenerateKey(rand.Reader)
        if err != nil { t.Fatal(err) }
        if _, err := Verify(sign(valid), "server", other, now); err == nil { t.Fatal("wrong key accepted") }
    })
    t.Run("invalid key length rejected", func(t *testing.T) {
        if _, err := Verify(sign(valid), "server", public[:len(public)-1], now); err == nil { t.Fatal("short key accepted") }
    })
    t.Run("invalid key encoding rejected", func(t *testing.T) {
        for _, key := range []string{"", "not-base64", base64.RawURLEncoding.EncodeToString(public[:31])} {
            if _, err := DecodePublicKey(key); err == nil { t.Fatalf("accepted invalid key %q", key) }
        }
    })
    t.Run("malformed signature rejected", func(t *testing.T) {
        value := sign(valid)
        parts := strings.Split(value, ".")
        parts[2] = base64.RawURLEncoding.EncodeToString([]byte("short"))
        if _, err := Verify(strings.Join(parts, "."), "server", public, now); err == nil { t.Fatal("short signature accepted") }
    })
    t.Run("oversized payload rejected", func(t *testing.T) {
        huge := valid
        huge.Subject = strings.Repeat("x", 5000)
        if _, err := Verify(sign(huge), "server", public, now); err == nil { t.Fatal("oversized payload accepted") }
    })
}
