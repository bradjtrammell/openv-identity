package main

import (
    "crypto/subtle"
    "encoding/base64"
    "net/http"
)

const maxLivenessBatch = 64

type livenessEntry struct {
    Subject string `json:"subject"`
    LoginSession string `json:"login_session"`
}

func canonicalLoginSession(v string) bool {
    if len(v) != 43 { return false }
    raw, err := base64.RawURLEncoding.DecodeString(v)
    return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == v
}

// registerSessionLiveness permits an enabled, authenticated game server to
// determine whether already-admitted ov2 player sessions remain authorized.
// The response never exposes bearer tokens, account metadata or credentials.
// A revoked login stays revoked even when the same subject logs in again.
func (s *Service) registerSessionLiveness(mux *http.ServeMux) {
    mux.HandleFunc("POST /api/v1/sessions/check", func(w http.ResponseWriter, r *http.Request) {
        var request struct {
            ServerID string `json:"server_id"`
            ServerSecret string `json:"server_secret"`
            Sessions []livenessEntry `json:"sessions"`
        }
        if !readJSON(w, r, &request) { return }
        if len(request.Sessions) == 0 || len(request.Sessions) > maxLivenessBatch {
            bad(w, 400, "invalid session batch")
            return
        }
        for _, item := range request.Sessions {
            if len(item.Subject) < 8 || len(item.Subject) > 256 || !canonicalLoginSession(item.LoginSession) {
                bad(w, 400, "invalid session reference")
                return
            }
        }
        s.mu.Lock()
        server, ok := s.db.Servers[request.ServerID]
        if !ok || !server.Enabled || subtle.ConstantTimeCompare(sha256sum(request.ServerSecret), mustDecode(server.SecretHash)) != 1 {
            s.mu.Unlock()
            bad(w, 401, "unauthorized server")
            return
        }
        now := s.now().Unix()
        active := make([]bool, len(request.Sessions))
        for i, item := range request.Sessions {
            login, found := s.db.Sessions[item.LoginSession]
            active[i] = found && login.Subject == item.Subject && login.Expires > now
        }
        s.mu.Unlock() // Never block logout behind a slow network writer.
        write(w, 200, map[string]any{"active": active})
    })
}
