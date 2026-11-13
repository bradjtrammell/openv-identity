package main

import (
 "path/filepath"
 "testing"
)

func TestAdministratorRevocationTerminatesMultiplayerSessions(t *testing.T) {
 t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-only-bootstrap-secret-000000000")
 path := filepath.Join(t.TempDir(), "identity.json")
 service, err := newService(path)
 if err != nil { t.Fatal(err) }
 h := service.handler()
 api(t,h,"POST","/api/v1/bootstrap","",map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"test-only-bootstrap-secret-000000000"},201)
 admin := api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"admin","password":"strong-password-one"},200)["access_token"].(string)
 api(t,h,"POST","/api/v1/admin/accounts",admin,map[string]string{"username":"player","password":"strong-password-two"},201)
 player := api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)["access_token"].(string)
 second := api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)["access_token"].(string)
 registered := api(t,h,"POST","/api/v1/servers/register",admin,map[string]string{"name":"Test Server","address":"127.0.0.1:30120"},201)
 id, secret := registered["id"].(string), registered["server_secret"].(string)
 ticket := api(t,h,"POST","/api/v1/tickets",player,map[string]string{"server_id":id},200)["ticket"].(string)
 redeemed := api(t,h,"POST","/api/v1/tickets/redeem","",map[string]string{"ticket":ticket,"server_id":id,"server_secret":secret},200)
 session := redeemed["login_session"].(string)
 subject := redeemed["subject"].(string)
 check := map[string]any{"server_id":id,"server_secret":secret,"sessions":[]map[string]string{{"subject":subject,"login_session":session}}}
 active := api(t,h,"POST","/api/v1/sessions/check","",check,200)["active"].([]any)
 if len(active)!=1 || active[0]!=true { t.Fatal("freshly redeemed session is not active") }
 endpoint := "/api/v1/admin/accounts/revoke-sessions"
 api(t,h,"POST",endpoint,player,map[string]string{"username":"player"},403)
 api(t,h,"POST",endpoint,admin,map[string]string{"username":"missing"},404)
 // Persistence failure must not disconnect active players.
 service.path = t.TempDir()
 api(t,h,"POST",endpoint,admin,map[string]string{"username":"player"},500)
 active = api(t,h,"POST","/api/v1/sessions/check","",check,200)["active"].([]any)
 if active[0]!=true { t.Fatal("failed persistence disconnected player") }
 service.path = path
 revoked := api(t,h,"POST",endpoint,admin,map[string]string{"username":" PLAYER "},200)
 if revoked["revoked"]!=float64(2) { t.Fatalf("expected two revoked sessions, got %v",revoked["revoked"]) }
 api(t,h,"GET","/api/v1/servers",player,nil,401)
 api(t,h,"GET","/api/v1/servers",second,nil,401)
 active = api(t,h,"POST","/api/v1/sessions/check","",check,200)["active"].([]any)
 if active[0]!=false { t.Fatal("revoked player still active on game server") }
 restarted, err := newService(path)
 if err != nil { t.Fatal(err) }
 active = api(t,restarted.handler(),"POST","/api/v1/sessions/check","",check,200)["active"].([]any)
 if active[0]!=false { t.Fatal("revocation did not persist across restart") }
 api(t,restarted.handler(),"POST","/api/v1/admin/accounts/revoke-sessions",admin,map[string]string{"username":"player"},200)
 // Re-authentication creates a new session without restoring the old one.
 newPlayer := api(t,restarted.handler(),"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)["access_token"].(string)
 api(t,restarted.handler(),"GET","/api/v1/servers",newPlayer,nil,200)
 active = api(t,restarted.handler(),"POST","/api/v1/sessions/check","",check,200)["active"].([]any)
 if active[0]!=false { t.Fatal("new login resurrected a revoked game session") }
}
