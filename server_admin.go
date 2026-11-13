package main

import (
 "net/http"
 "strings"
)

// registerServerAdministration lets a community operator revoke a compromised
// server credential without restarting Identity or changing player accounts.
// Rotating the credential immediately invalidates the previous secret for all
// ticket redemption requests. Disabling a server also prevents ticket issuance.
func (s *Service) registerServerAdministration(mux *http.ServeMux) {
 mux.HandleFunc("POST /api/v1/admin/servers/rotate-secret", func(w http.ResponseWriter, r *http.Request) {
  var request struct { ServerID string `json:"server_id"` }
  if !readJSON(w, r, &request) { return }
  s.mu.Lock()
  defer s.mu.Unlock()
  account, authorized := s.bearer(r)
  if !authorized || !account.Admin { bad(w, http.StatusForbidden, "admin required"); return }
  server, exists := s.db.Servers[request.ServerID]
  if !exists { bad(w, http.StatusNotFound, "server not found"); return }
  secret := randomID()
  previous := server
  server.SecretHash = b64(sha256sum(secret))
  s.db.Servers[request.ServerID] = server
  if err := s.saveLocked(); err != nil {
   s.db.Servers[request.ServerID] = previous
   bad(w, http.StatusInternalServerError, "storage error")
   return
  }
  write(w, http.StatusOK, map[string]string{"server_id":request.ServerID,"server_secret":secret})
 })
 mux.HandleFunc("POST /api/v1/admin/servers/set-enabled", func(w http.ResponseWriter, r *http.Request) {
  var request struct { ServerID string `json:"server_id"`; Enabled *bool `json:"enabled"` }
  if !readJSON(w, r, &request) { return }
  if request.Enabled == nil { bad(w, http.StatusBadRequest, "enabled is required"); return }
  s.mu.Lock()
  defer s.mu.Unlock()
  account, authorized := s.bearer(r)
  if !authorized || !account.Admin { bad(w, http.StatusForbidden, "admin required"); return }
  server, exists := s.db.Servers[request.ServerID]
  if !exists { bad(w, http.StatusNotFound, "server not found"); return }
  previous := server
  server.Enabled = *request.Enabled
  s.db.Servers[request.ServerID] = server
  if err := s.saveLocked(); err != nil {
   s.db.Servers[request.ServerID] = previous
   bad(w, http.StatusInternalServerError, "storage error")
   return
  }
  write(w, http.StatusOK, map[string]any{"server_id":request.ServerID,"enabled":server.Enabled})
 })
 mux.HandleFunc("POST /api/v1/admin/servers/update-address", func(w http.ResponseWriter, r *http.Request) {
  var request struct { ServerID string `json:"server_id"`; Address string `json:"address"` }
  if !readJSON(w, r, &request) { return }
  s.mu.Lock()
  defer s.mu.Unlock()
  account, authorized := s.bearer(r)
  if !authorized || !account.Admin { bad(w, http.StatusForbidden, "admin required"); return }
  if !validAddress(request.Address) { bad(w, http.StatusBadRequest, "invalid server address"); return }
  server, exists := s.db.Servers[request.ServerID]
  if !exists { bad(w, http.StatusNotFound, "server not found"); return }
  previous := server
  server.Address = request.Address
  s.db.Servers[request.ServerID] = server
  if err := s.saveLocked(); err != nil {
   s.db.Servers[request.ServerID] = previous
   bad(w, http.StatusInternalServerError, "storage error")
   return
  }
  write(w, http.StatusOK, map[string]string{"server_id":request.ServerID,"address":server.Address})
 })

 // Revoking all logins for an account invalidates outstanding ov2 tickets
 // and causes connected game servers' session-liveness checks to fail.
 mux.HandleFunc("POST /api/v1/admin/accounts/revoke-sessions", func(w http.ResponseWriter, r *http.Request) {
  var request struct { Username string `json:"username"` }
  if !readJSON(w, r, &request) { return }
  s.mu.Lock()
  defer s.mu.Unlock()
  actor, authorized := s.bearer(r)
  if !authorized || !actor.Admin { bad(w, http.StatusForbidden, "admin required"); return }
  username := strings.ToLower(strings.TrimSpace(request.Username))
  account, exists := s.db.Accounts[username]
  if !exists { bad(w, http.StatusNotFound, "account not found"); return }
  removed := make(map[string]Session)
  for key, session := range s.db.Sessions {
   if session.Subject == account.ID {
    removed[key] = session
    delete(s.db.Sessions, key)
   }
  }
  if len(removed) != 0 {
   if err := s.saveLocked(); err != nil {
    for key, session := range removed { s.db.Sessions[key] = session }
    bad(w, http.StatusInternalServerError, "storage error")
    return
   }
  }
  write(w, http.StatusOK, map[string]any{"username":username,"revoked":len(removed)})
 })

}
