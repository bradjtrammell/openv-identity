package main

import (
 "path/filepath"
 "testing"
)

func TestServerCredentialLifecycle(t *testing.T) {
 t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-only-bootstrap-secret-000000000")
 path := filepath.Join(t.TempDir(), "identity.json")
 service, err := newService(path)
 if err != nil { t.Fatal(err) }
 handler := service.handler()
 api(t, handler, "POST", "/api/v1/bootstrap", "", map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"test-only-bootstrap-secret-000000000"}, 201)
 admin := api(t, handler, "POST", "/api/v1/auth/login", "", map[string]string{"username":"admin","password":"strong-password-one"}, 200)["access_token"].(string)
 api(t, handler, "POST", "/api/v1/admin/accounts", admin, map[string]string{"username":"player","password":"strong-password-two"}, 201)
 player := api(t, handler, "POST", "/api/v1/auth/login", "", map[string]string{"username":"player","password":"strong-password-two"}, 200)["access_token"].(string)
 registered := api(t, handler, "POST", "/api/v1/servers/register", admin, map[string]string{"name":"Test Server","address":"127.0.0.1:30120"}, 201)
 id, oldSecret := registered["id"].(string), registered["server_secret"].(string)
 rotate := map[string]string{"server_id":id}
 api(t, handler, "POST", "/api/v1/admin/servers/update-address", "", map[string]string{"server_id":id,"address":"127.0.0.1:30121"}, 403)
 api(t, handler, "POST", "/api/v1/admin/servers/update-address", player, map[string]string{"server_id":id,"address":"127.0.0.1:30121"}, 403)
 api(t, handler, "POST", "/api/v1/admin/servers/update-address", admin, map[string]string{"server_id":id,"address":"not-an-address"}, 400)
 api(t, handler, "POST", "/api/v1/admin/servers/update-address", admin, map[string]string{"server_id":"missing","address":"127.0.0.1:30121"}, 404)
 api(t, handler, "POST", "/api/v1/admin/servers/update-address", admin, map[string]string{"server_id":id,"address":"127.0.0.1:30121"}, 200)
 listed := api(t, handler, "GET", "/api/v1/servers", player, nil, 200)["servers"].([]any)
 if len(listed) != 1 || listed[0].(map[string]any)["address"] != "127.0.0.1:30121" { t.Fatal("updated server address not visible to clients") }
 api(t, handler, "POST", "/api/v1/admin/servers/rotate-secret", "", rotate, 403)
 api(t, handler, "POST", "/api/v1/admin/servers/rotate-secret", player, rotate, 403)
 api(t, handler, "POST", "/api/v1/admin/servers/rotate-secret", admin, map[string]string{"server_id":"missing"}, 404)
 ticket := api(t, handler, "POST", "/api/v1/tickets", player, map[string]string{"server_id":id}, 200)["ticket"].(string)
 newSecret := api(t, handler, "POST", "/api/v1/admin/servers/rotate-secret", admin, rotate, 200)["server_secret"].(string)
 if oldSecret == newSecret { t.Fatal("rotation reused server credential") }
 api(t, handler, "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":oldSecret,"ticket":ticket}, 401)
 api(t, handler, "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":newSecret,"ticket":ticket}, 200)
 api(t, handler, "POST", "/api/v1/admin/servers/set-enabled", admin, map[string]any{"server_id":id}, 400)
 api(t, handler, "POST", "/api/v1/admin/servers/set-enabled", player, map[string]any{"server_id":id,"enabled":false}, 403)
 api(t, handler, "POST", "/api/v1/admin/servers/set-enabled", admin, map[string]any{"server_id":id,"enabled":false}, 200)
 api(t, handler, "POST", "/api/v1/tickets", player, map[string]string{"server_id":id}, 404)
 api(t, handler, "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":newSecret,"ticket":ticket}, 401)
 restarted, err := newService(path)
 if err != nil { t.Fatal(err) }
 listedAfterRestart := api(t, restarted.handler(), "GET", "/api/v1/servers", player, nil, 200)["servers"].([]any)
 if len(listedAfterRestart) != 0 { t.Fatal("disabled server appeared in listing") }
 if restarted.db.Servers[id].Address != "127.0.0.1:30121" { t.Fatal("updated address did not survive restart") }
 api(t, restarted.handler(), "POST", "/api/v1/tickets", player, map[string]string{"server_id":id}, 404)
 api(t, restarted.handler(), "POST", "/api/v1/admin/servers/set-enabled", admin, map[string]any{"server_id":id,"enabled":true}, 200)
 ticket2 := api(t, restarted.handler(), "POST", "/api/v1/tickets", player, map[string]string{"server_id":id}, 200)["ticket"].(string)
 api(t, restarted.handler(), "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":oldSecret,"ticket":ticket2}, 401)
 api(t, restarted.handler(), "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":newSecret,"ticket":ticket2}, 200)
}

func TestFailedPersistenceDoesNotConsumeTicketOrRetainLogin(t *testing.T) {
 t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-only-bootstrap-secret-000000000")
 path := filepath.Join(t.TempDir(), "identity.json")
 service, err := newService(path)
 if err != nil { t.Fatal(err) }
 handler := service.handler()
 api(t, handler, "POST", "/api/v1/bootstrap", "", map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"test-only-bootstrap-secret-000000000"}, 201)
 admin := api(t, handler, "POST", "/api/v1/auth/login", "", map[string]string{"username":"admin","password":"strong-password-one"}, 200)["access_token"].(string)
 registered := api(t, handler, "POST", "/api/v1/servers/register", admin, map[string]string{"name":"Test Server","address":"127.0.0.1:30120"}, 201)
 id, secret := registered["id"].(string), registered["server_secret"].(string)
 ticket := api(t, handler, "POST", "/api/v1/tickets", admin, map[string]string{"server_id":id}, 200)["ticket"].(string)
 originalPath := service.path
 // A directory cannot be replaced by the temporary JSON file on rename.
 service.path = t.TempDir()
 api(t, handler, "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":secret,"ticket":ticket}, 500)
 if len(service.db.Used) != 0 { t.Fatal("failed redemption consumed a ticket in memory") }
 before := len(service.db.Sessions)
 api(t, handler, "POST", "/api/v1/auth/login", "", map[string]string{"username":"admin","password":"strong-password-one"}, 500)
 if len(service.db.Sessions) != before { t.Fatal("failed login retained a session in memory") }
 service.path = originalPath
 api(t, handler, "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":secret,"ticket":ticket}, 200)
 api(t, handler, "POST", "/api/v1/tickets/redeem", "", map[string]string{"server_id":id,"server_secret":secret,"ticket":ticket}, 409)
}


func TestFailedPersistenceRollsBackAccountServerAndLogout(t *testing.T) {
 t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-only-bootstrap-secret-000000000")
 path := filepath.Join(t.TempDir(), "identity.json")
 service, err := newService(path)
 if err != nil { t.Fatal(err) }
 handler := service.handler()
 service.path = t.TempDir()
 api(t, handler, "POST", "/api/v1/bootstrap", "", map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"test-only-bootstrap-secret-000000000"}, 500)
 if len(service.db.Accounts) != 0 { t.Fatal("failed bootstrap left an administrator in memory") }
 service.path = path
 api(t, handler, "POST", "/api/v1/bootstrap", "", map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"test-only-bootstrap-secret-000000000"}, 201)
 admin := api(t, handler, "POST", "/api/v1/auth/login", "", map[string]string{"username":"admin","password":"strong-password-one"}, 200)["access_token"].(string)
 service.path = t.TempDir()
 api(t, handler, "POST", "/api/v1/admin/accounts", admin, map[string]string{"username":"player","password":"strong-password-two"}, 500)
 if _, ok := service.db.Accounts["player"]; ok { t.Fatal("failed account creation left an account in memory") }
 api(t, handler, "POST", "/api/v1/servers/register", admin, map[string]string{"name":"Test Server","address":"127.0.0.1:30120"}, 500)
 if len(service.db.Servers) != 0 { t.Fatal("failed server registration left a server in memory") }
 api(t, handler, "POST", "/api/v1/auth/logout", admin, nil, 500)
 if _, ok := service.bearerForTest(admin); !ok { t.Fatal("failed logout revoked the login in memory") }
 service.path = path
 api(t, handler, "POST", "/api/v1/admin/accounts", admin, map[string]string{"username":"player","password":"strong-password-two"}, 201)
 api(t, handler, "POST", "/api/v1/servers/register", admin, map[string]string{"name":"Test Server","address":"127.0.0.1:30120"}, 201)
 api(t, handler, "POST", "/api/v1/auth/logout", admin, nil, 200)
 if _, ok := service.bearerForTest(admin); ok { t.Fatal("successful logout did not revoke the login") }
}

func (s *Service) bearerForTest(token string) (Account, bool) {
 s.mu.Lock()
 defer s.mu.Unlock()
 session, ok := s.db.Sessions[b64(sha256sum(token))]
 if !ok || session.Expires <= s.now().Unix() { return Account{}, false }
 for _, account := range s.db.Accounts { if account.ID == session.Subject { return account, true } }
 return Account{}, false
}
