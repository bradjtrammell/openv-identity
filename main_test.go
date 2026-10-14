package main

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "testing"
)

func api(t *testing.T,h http.Handler,method,path,token string,input any,want int) map[string]any{
 t.Helper();var b []byte;if input!=nil{var e error;b,e=json.Marshal(input);if e!=nil{t.Fatal(e)}}
 r:=httptest.NewRequest(method,path,bytes.NewReader(b));r.RemoteAddr="127.0.0.1:35445";if token!=""{r.Header.Set("Authorization","Bearer "+token)}
 w:=httptest.NewRecorder();h.ServeHTTP(w,r);if w.Code!=want{t.Fatalf("%s %s: got %d, expected %d: %s",method,path,w.Code,want,w.Body.String())}
 out:=map[string]any{};if e:=json.Unmarshal(w.Body.Bytes(),&out);e!=nil{t.Fatal(e)};return out
}
func TestIdentityLifecycle(t *testing.T){
 t.Setenv("OPENV_BOOTSTRAP_SECRET","test-only-bootstrap-secret-000000000")
 path:=filepath.Join(t.TempDir(),"identity.json")
 s,e:=newService(path);if e!=nil{t.Fatal(e)};h:=s.handler()
 secret:=os.Getenv("OPENV_BOOTSTRAP_SECRET")
 api(t,h,"POST","/api/v1/bootstrap","",map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":"bad"},403)
 api(t,h,"POST","/api/v1/bootstrap","",map[string]string{"username":"admin","password":"strong-password-one","bootstrap_secret":secret},201)
 api(t,h,"POST","/api/v1/bootstrap","",map[string]string{"username":"admin2","password":"strong-password-two","bootstrap_secret":secret},403)
 login:=api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"admin","password":"strong-password-one"},200)
 token:=login["access_token"].(string)
 api(t,h,"POST","/api/v1/admin/accounts",token,map[string]string{"username":"player","password":"strong-password-two"},201)
 registered:=api(t,h,"POST","/api/v1/servers/register",token,map[string]string{"name":"Test Server","address":"127.0.0.1:30120"},201)
 id:=registered["id"].(string);serverSecret:=registered["server_secret"].(string)
 player:=api(t,h,"POST","/api/v1/auth/login","",map[string]string{"username":"player","password":"strong-password-two"},200)
 playerToken:=player["access_token"].(string)
 api(t,h,"GET","/api/v1/servers",playerToken,nil,200)
 ticket:=api(t,h,"POST","/api/v1/tickets",playerToken,map[string]string{"server_id":id},200)["ticket"].(string)
 body:=map[string]string{"ticket":ticket,"server_id":id,"server_secret":serverSecret}
 api(t,h,"POST","/api/v1/tickets/redeem","",body,200)
 api(t,h,"POST","/api/v1/tickets/redeem","",body,409)
 restarted,e:=newService(path);if e!=nil{t.Fatal(e)}
 api(t,restarted.handler(),"POST","/api/v1/tickets/redeem","",body,409)
 api(t,restarted.handler(),"POST","/api/v1/auth/logout",playerToken,nil,200)
 api(t,restarted.handler(),"GET","/api/v1/servers",playerToken,nil,401)
}
func TestInvalidTicket(t *testing.T){
 s,e:=newService(filepath.Join(t.TempDir(),"data.json"));if e!=nil{t.Fatal(e)}
 if _,e:=s.verifyTicket("invalid","a");e==nil{t.Fatal("invalid ticket accepted")}
}
