package main

import (
 "path/filepath"
 "testing"
)

func TestPlayerPasswordChangeRevokesAllSessionsAndTickets(t *testing.T) {
 t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-only-bootstrap-secret-000000000")
 path := filepath.Join(t.TempDir(), "identity.json")
 s, err := newService(path)
 if err != nil { t.Fatal(err) }
 h := s.handler()
 api(t,h,"POST","/api/v1/bootstrap","",map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"test-only-bootstrap-secret-000000000"},201)
 admin := api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"admin","password":"strong-password-one"},200)["access_token"].(string)
 api(t,h,"POST","/api/v1/admin/accounts",admin,map[string]string{"username":"player","password":"strong-password-two"},201)
 player := api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)["access_token"].(string)
 second := api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)["access_token"].(string)
 registered := api(t,h,"POST","/api/v1/servers/register",admin,map[string]string{"name":"Test Server","address":"127.0.0.1:30120"},201)
 id, secret := registered["id"].(string), registered["server_secret"].(string)
 ticket := api(t,h,"POST","/api/v1/tickets",player,map[string]string{"server_id":id},200)["ticket"].(string)
 change := map[string]string{"current_password":"strong-password-two","new_password":"strong-password-three"}
 endpoint := "/api/v1/auth/change-password"
 api(t,h,"POST",endpoint,"",change,401)
 api(t,h,"POST",endpoint,player,map[string]string{"current_password":"incorrect-password","new_password":"strong-password-three"},401)
 api(t,h,"POST",endpoint,player,map[string]string{"current_password":"strong-password-two","new_password":"short"},400)
 api(t,h,"GET","/api/v1/servers",player,nil,200)
 originalPath := s.path
 s.path = t.TempDir()
 api(t,h,"POST",endpoint,player,change,500)
 s.path = originalPath
 api(t,h,"GET","/api/v1/servers",player,nil,200)
 api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)
 result := api(t,h,"POST",endpoint,player,change,200)
 if result["revoked"] != float64(3) { t.Fatalf("expected three revoked sessions, got %v",result["revoked"]) }
 api(t,h,"GET","/api/v1/servers",player,nil,401)
 api(t,h,"GET","/api/v1/servers",second,nil,401)
 api(t,h,"POST","/api/v1/tickets/redeem","",map[string]string{"server_id":id,"server_secret":secret,"ticket":ticket},401)
 api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},401)
 restarted, err := newService(path)
 if err != nil { t.Fatal(err) }
 fresh := api(t,restarted.handler(),"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-three"},200)["access_token"].(string)
 api(t,restarted.handler(),"GET","/api/v1/servers",fresh,nil,200)
 api(t,restarted.handler(),"POST","/api/v1/tickets/redeem","",map[string]string{"server_id":id,"server_secret":secret,"ticket":ticket},401)
}
