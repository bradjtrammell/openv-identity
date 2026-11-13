package main

import (
 "crypto/subtle"
 "encoding/base64"
 "net/http"
 "strings"
)

// registerPlayerCredentials permits authenticated players to replace their own
// password without administrator intervention. The change and revocation of
// every existing login are persisted as a single state transition.
func (s *Service) registerPlayerCredentials(mux *http.ServeMux) {
 mux.HandleFunc("POST /api/v1/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
  var request struct {
   CurrentPassword string `json:"current_password"`
   NewPassword string `json:"new_password"`
  }
  if !readJSON(w, r, &request) { return }
  s.mu.Lock()
  defer s.mu.Unlock()
  actor, ok := s.bearer(r)
  if !ok { bad(w, http.StatusUnauthorized, "unauthorized"); return }
  if len(request.NewPassword) < 12 || len(request.NewPassword) > 512 {
   bad(w, http.StatusBadRequest, "password must be 12-512 characters")
   return
  }
  if strings.TrimSpace(request.CurrentPassword) == "" {
   bad(w, http.StatusBadRequest, "current password is required")
   return
  }
  salt, err := base64.RawURLEncoding.DecodeString(actor.Salt)
  if err != nil { bad(w, http.StatusInternalServerError, "account error"); return }
  expected, err := base64.RawURLEncoding.DecodeString(actor.Hash)
  if err != nil { bad(w, http.StatusInternalServerError, "account error"); return }
  if subtle.ConstantTimeCompare(derive(request.CurrentPassword, salt), expected) != 1 {
   bad(w, http.StatusUnauthorized, "invalid current password")
   return
  }
  previous := actor
  newSalt := randomBytes(16)
  actor.Salt = b64(newSalt)
  actor.Hash = b64(derive(request.NewPassword, newSalt))
  s.db.Accounts[actor.Username] = actor
  removed := make(map[string]Session)
  for key, session := range s.db.Sessions {
   if session.Subject == actor.ID {
    removed[key] = session
    delete(s.db.Sessions, key)
   }
  }
  if err := s.saveLocked(); err != nil {
   s.db.Accounts[actor.Username] = previous
   for key, session := range removed { s.db.Sessions[key] = session }
   bad(w, http.StatusInternalServerError, "storage error")
   return
  }
  write(w, http.StatusOK, map[string]any{"ok":true,"revoked":len(removed)})
 })
}
