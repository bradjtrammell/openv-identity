package ticket

import (
    "bytes"
    "encoding/json"
    "errors"
)

// decodeStrictClaims rejects ambiguous, duplicated or extended v1/v2 claim sets.
// This matters even for signed tickets: two implementations must not interpret
// the same signed bytes as different subjects, audiences or expiration times.
// v2 requires exactly one sid; v1 must not carry a sid.
func decodeStrictClaims(raw []byte, claims *Claims) error {
    const invalid = "invalid signed claims"
    allowed := map[string]bool{
        "iss": true, "sub": true, "aud": true, "jti": true,
        "iat": true, "exp": true, "v": true, "sid": true,
    }
    seen := make(map[string]bool, len(allowed))
    decoder := json.NewDecoder(bytes.NewReader(raw))
    start, err := decoder.Token()
    if err != nil || start != json.Delim('{') {
        return errors.New(invalid)
    }
    for decoder.More() {
        token, err := decoder.Token()
        key, ok := token.(string)
        if err != nil || !ok || !allowed[key] || seen[key] {
            return errors.New(invalid)
        }
        seen[key] = true
        var value json.RawMessage
        if err := decoder.Decode(&value); err != nil {
            return errors.New(invalid)
        }
    }
    end, err := decoder.Token()
    if err != nil || end != json.Delim('}') {
        return errors.New(invalid)
    }
    // Unmarshal also rejects trailing data and incorrect claim value types.
    if err := json.Unmarshal(raw, claims); err != nil {
        return errors.New(invalid)
    }
    expected := 7
    if claims.Version == 2 { expected = 8 }
    if (claims.Version != 1 && claims.Version != 2) || len(seen) != expected || (claims.Version == 2) != seen["sid"] {
        return errors.New(invalid)
    }
    return nil
}
