package main

import (
 "crypto/ed25519"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "sync"
 "time"
)

const maxBody = 16 << 10
const iterations = 310000
const ticketLifetime = 90*time.Second
const sessionLifetime = 12*time.Hour
var usernamePattern = regexp.MustCompile("^[a-z0-9][a-z0-9_.-]{2,31}$")

type Account struct { ID string `json:"id"`; Username string `json:"username"`; Salt string `json:"salt"`; Hash string `json:"hash"`; Admin bool `json:"admin"` }
type Server struct { ID string `json:"id"`; Name string `json:"name"`; Address string `json:"address"`; SecretHash string `json:"secret_hash"`; Enabled bool `json:"enabled"` }
type Session struct { Subject string `json:"subject"`; Expires int64 `json:"expires"` }
type Database struct { Accounts map[string]Account `json:"accounts"`; Servers map[string]Server `json:"servers"`; Sessions map[string]Session `json:"sessions"`; Used map[string]int64 `json:"used"`; SigningKey string `json:"signing_key"` }
type loginAttempt struct { Count int; Until int64 }
type Service struct { mu sync.Mutex; path string; db Database; signer ed25519.PrivateKey; now func()time.Time; loginFailures map[string]loginAttempt }
type TokenClaims struct { Issuer string `json:"iss"`; Subject string `json:"sub"`; Audience string `json:"aud"`; ID string `json:"jti"`; Issued int64 `json:"iat"`; Expires int64 `json:"exp"`; Version int `json:"v"` }

func randomBytes(n int) []byte { b:=make([]byte,n);if _,e:=rand.Read(b);e!=nil{panic(e)};return b }
func randomID()string{return base64.RawURLEncoding.EncodeToString(randomBytes(24))}
func b64(b []byte)string{return base64.RawURLEncoding.EncodeToString(b)}
func sha256sum(v string)[]byte{h:=sha256.Sum256([]byte(v));return h[:]}
func derive(password string,salt []byte)[]byte{
 var idx [4]byte;idx[3]=1
 mac:=hmac.New(sha256.New,[]byte(password));mac.Write(salt);mac.Write(idx[:]);u:=mac.Sum(nil);out:=append([]byte(nil),u...)
 for i:=1;i<iterations;i++{mac=hmac.New(sha256.New,[]byte(password));mac.Write(u);u=mac.Sum(nil);for j:=range out{out[j]^=u[j]}}
 return out
}
func newService(path string)(*Service,error){
 s:=&Service{path:path,now:time.Now,loginFailures:map[string]loginAttempt{}}
 raw,e:=os.ReadFile(path);if e==nil{if e=json.Unmarshal(raw,&s.db);e!=nil{return nil,fmt.Errorf("parse store: %w",e)}}else if !errors.Is(e,os.ErrNotExist){return nil,e}
 if s.db.Accounts==nil{s.db.Accounts=map[string]Account{}};if s.db.Servers==nil{s.db.Servers=map[string]Server{}};if s.db.Sessions==nil{s.db.Sessions=map[string]Session{}};if s.db.Used==nil{s.db.Used=map[string]int64{}}
 if s.db.SigningKey==""{_,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{return nil,e};s.db.SigningKey=b64(key);if e=s.saveLocked();e!=nil{return nil,e}}
 key,e:=base64.RawURLEncoding.DecodeString(s.db.SigningKey);if e!=nil||len(key)!=ed25519.PrivateKeySize{return nil,errors.New("invalid signing key")}
 s.signer=ed25519.PrivateKey(key);return s,nil
}
func(s *Service)saveLocked()error{
 data,e:=json.MarshalIndent(s.db,"","  ");if e!=nil{return e};if e=os.MkdirAll(filepath.Dir(s.path),0700);e!=nil{return e}
 tmp:=s.path+".tmp";if e=os.WriteFile(tmp,data,0600);e!=nil{return e};return os.Rename(tmp,s.path)
}
func(s *Service)publicKey()string{return b64(s.signer.Public().(ed25519.PublicKey))}
func write(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.Header().Set("Cache-Control","no-store");w.WriteHeader(status);_ =json.NewEncoder(w).Encode(v)}
func bad(w http.ResponseWriter,status int,msg string){write(w,status,map[string]string{"error":msg})}
func readJSON(w http.ResponseWriter,r *http.Request,out any)bool{
 r.Body=http.MaxBytesReader(w,r.Body,maxBody);d:=json.NewDecoder(r.Body);d.DisallowUnknownFields();if e:=d.Decode(out);e!=nil{bad(w,400,"invalid JSON body");return false}
 var extra any;if d.Decode(&extra)!=io.EOF{bad(w,400,"unexpected trailing JSON");return false};return true
}
func(s *Service)bearer(r *http.Request)(Account,bool){
 value:=r.Header.Get("Authorization");if !strings.HasPrefix(value,"Bearer "){return Account{},false};token:=strings.TrimPrefix(value,"Bearer ");sess,ok:=s.db.Sessions[b64(sha256sum(token))]
 if !ok||sess.Expires<=s.now().Unix(){return Account{},false};for _,a:=range s.db.Accounts{if a.ID==sess.Subject{return a,true}};return Account{},false
}
func(s *Service)createAccount(username,password string,admin bool)(Account,error){
 username=strings.ToLower(strings.TrimSpace(username));if !usernamePattern.MatchString(username){return Account{},errors.New("username must be 3-32 lowercase letters, digits, dots, hyphens or underscores")}
 if len(password)<12||len(password)>512{return Account{},errors.New("password must be 12-512 characters")}
 if _,ok:=s.db.Accounts[username];ok{return Account{},errors.New("username already exists")}
 salt:=randomBytes(16);a:=Account{ID:randomID(),Username:username,Salt:b64(salt),Hash:b64(derive(password,salt)),Admin:admin};s.db.Accounts[username]=a;return a,nil
}
func(s *Service)verifyTicket(value,audience string)(TokenClaims,error){
 parts:=strings.Split(value,".");if len(parts)!=3||parts[0]!="ov1"{return TokenClaims{},errors.New("invalid ticket format")}
 raw,e:=base64.RawURLEncoding.DecodeString(parts[1]);if e!=nil||len(raw)>4096{return TokenClaims{},errors.New("invalid ticket payload")}
 sig,e:=base64.RawURLEncoding.DecodeString(parts[2]);if e!=nil||!ed25519.Verify(s.signer.Public().(ed25519.PublicKey),[]byte(parts[1]),sig){return TokenClaims{},errors.New("invalid ticket signature")}
 var c TokenClaims;if e=json.Unmarshal(raw,&c);e!=nil{return c,errors.New("invalid ticket claims")}
 now:=s.now().Unix();if c.Issued>now||c.Expires<=c.Issued||c.Version!=1||c.Issuer!="openv-community"||c.Audience!=audience||c.Subject==""||c.ID==""||c.Expires<=now||c.Expires-c.Issued>int64(ticketLifetime.Seconds()){return c,errors.New("invalid or expired ticket")}
 return c,nil
}
func validAddress(v string)bool{h,p,e:=net.SplitHostPort(v);if e!=nil||h==""||p==""{return false};n,e:=strconv.Atoi(p);return e==nil&&n>=1&&n<=65535&&len(v)<=255}
func mustDecode(v string)[]byte{b,_:=base64.RawURLEncoding.DecodeString(v);return b}
func withHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Referrer-Policy","no-referrer");next.ServeHTTP(w,r)})}
func(s *Service)handler()http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /health",func(w http.ResponseWriter,r *http.Request){write(w,200,map[string]any{"status":"ok","service":"openv-identity"})})
 mux.HandleFunc("GET /.well-known/openv-identity",func(w http.ResponseWriter,r *http.Request){write(w,200,map[string]any{"version":1,"keys":"/api/v1/keys","servers":"/api/v1/servers","login":"/api/v1/auth/login"})})
 mux.HandleFunc("GET /api/v1/keys",func(w http.ResponseWriter,r *http.Request){write(w,200,map[string]any{"alg":"Ed25519","kid":"community-1","public_key":s.publicKey()})})
 mux.HandleFunc("POST /api/v1/bootstrap",func(w http.ResponseWriter,r *http.Request){
 var v struct{Username string `json:"username"`;Password string `json:"password"`;BootstrapSecret string `json:"bootstrap_secret"`};if !readJSON(w,r,&v){return};s.mu.Lock();defer s.mu.Unlock()
 if len(s.db.Accounts)!=0{bad(w,403,"bootstrap already completed");return};expected:=os.Getenv("OPENV_BOOTSTRAP_SECRET");if len(expected)<24||subtle.ConstantTimeCompare([]byte(v.BootstrapSecret),[]byte(expected))!=1{bad(w,403,"invalid bootstrap secret");return}
 a,e:=s.createAccount(v.Username,v.Password,true);if e!=nil{bad(w,400,e.Error());return};if e=s.saveLocked();e!=nil{bad(w,500,"storage error");return};write(w,201,map[string]string{"id":a.ID,"username":a.Username})
 })
 mux.HandleFunc("POST /api/v1/admin/accounts",func(w http.ResponseWriter,r *http.Request){
 var v struct{Username string `json:"username"`;Password string `json:"password"`};if !readJSON(w,r,&v){return};s.mu.Lock();defer s.mu.Unlock();a,ok:=s.bearer(r);if !ok||!a.Admin{bad(w,403,"admin required");return}
 created,e:=s.createAccount(v.Username,v.Password,false);if e!=nil{bad(w,400,e.Error());return};if e=s.saveLocked();e!=nil{bad(w,500,"storage error");return};write(w,201,map[string]string{"id":created.ID,"username":created.Username})
 })
 mux.HandleFunc("POST /api/v1/auth/login",func(w http.ResponseWriter,r *http.Request){
 var v struct{Username string `json:"username"`;Password string `json:"password"`};if !readJSON(w,r,&v){return};s.mu.Lock();defer s.mu.Unlock()
 remoteIP,_,e:=net.SplitHostPort(r.RemoteAddr);if e!=nil{remoteIP=r.RemoteAddr};loginKey:=strings.ToLower(strings.TrimSpace(v.Username))+"|"+remoteIP
 if f,ok:=s.loginFailures[loginKey];ok&&f.Count>=5&&f.Until>s.now().Unix(){bad(w,429,"too many login attempts");return}
 loginFailed:=func(){f:=s.loginFailures[loginKey];if f.Until<=s.now().Unix(){f.Count=0};f.Count++;f.Until=s.now().Add(5*time.Minute).Unix();s.loginFailures[loginKey]=f}
 a,ok:=s.db.Accounts[strings.ToLower(v.Username)];if !ok{loginFailed();bad(w,401,"invalid credentials");return}
 salt,e:=base64.RawURLEncoding.DecodeString(a.Salt);if e!=nil{bad(w,500,"account error");return};expected,_:=base64.RawURLEncoding.DecodeString(a.Hash)
 if subtle.ConstantTimeCompare(derive(v.Password,salt),expected)!=1{loginFailed();bad(w,401,"invalid credentials");return};delete(s.loginFailures,loginKey)
 token:=randomID();s.db.Sessions[b64(sha256sum(token))]=Session{Subject:a.ID,Expires:s.now().Add(sessionLifetime).Unix()};if e=s.saveLocked();e!=nil{bad(w,500,"storage error");return}
 write(w,200,map[string]any{"access_token":token,"expires_in":int(sessionLifetime.Seconds()),"user":map[string]any{"id":a.ID,"username":a.Username,"admin":a.Admin}})
 })
 mux.HandleFunc("POST /api/v1/auth/logout",func(w http.ResponseWriter,r *http.Request){
 s.mu.Lock();defer s.mu.Unlock();v:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ");if _,ok:=s.bearer(r);!ok{bad(w,401,"unauthorized");return}
 delete(s.db.Sessions,b64(sha256sum(v)));if e:=s.saveLocked();e!=nil{bad(w,500,"storage error");return};write(w,200,map[string]bool{"ok":true})
 })
 mux.HandleFunc("POST /api/v1/servers/register",func(w http.ResponseWriter,r *http.Request){
 var v struct{Name string `json:"name"`;Address string `json:"address"`};if !readJSON(w,r,&v){return};s.mu.Lock();defer s.mu.Unlock()
 a,ok:=s.bearer(r);if !ok||!a.Admin{bad(w,403,"admin required");return}
 if len(v.Name)<2||len(v.Name)>80||len(v.Address)>255||!validAddress(v.Address){bad(w,400,"invalid server name or address");return}
 id:=randomID();secret:=randomID();s.db.Servers[id]=Server{ID:id,Name:v.Name,Address:v.Address,SecretHash:b64(sha256sum(secret)),Enabled:true}
 if e:=s.saveLocked();e!=nil{bad(w,500,"storage error");return};write(w,201,map[string]string{"id":id,"name":v.Name,"server_secret":secret})
 })
 mux.HandleFunc("GET /api/v1/servers",func(w http.ResponseWriter,r *http.Request){
 s.mu.Lock();defer s.mu.Unlock();if _,ok:=s.bearer(r);!ok{bad(w,401,"unauthorized");return}
 type listed struct{ID string `json:"id"`;Name string `json:"name"`;Address string `json:"address"`}
 out:=make([]listed,0,len(s.db.Servers));for _,v:=range s.db.Servers{if v.Enabled{out=append(out,listed{v.ID,v.Name,v.Address})}};write(w,200,map[string]any{"servers":out})
 })
 mux.HandleFunc("POST /api/v1/tickets",func(w http.ResponseWriter,r *http.Request){
 var v struct{ServerID string `json:"server_id"`};if !readJSON(w,r,&v){return};s.mu.Lock();defer s.mu.Unlock()
 a,ok:=s.bearer(r);if !ok{bad(w,401,"unauthorized");return};server,ok:=s.db.Servers[v.ServerID];if !ok||!server.Enabled{bad(w,404,"server not found");return}
 now:=s.now();claims:=TokenClaims{Issuer:"openv-community",Subject:a.ID,Audience:v.ServerID,ID:randomID(),Issued:now.Unix(),Expires:now.Add(ticketLifetime).Unix(),Version:1}
 payload,_:=json.Marshal(claims);encoded:=b64(payload);sig:=ed25519.Sign(s.signer,[]byte(encoded));write(w,200,map[string]any{"ticket":"ov1."+encoded+"."+b64(sig),"expires_in":int(ticketLifetime.Seconds())})
 })
 mux.HandleFunc("POST /api/v1/tickets/redeem",func(w http.ResponseWriter,r *http.Request){
 var v struct{Ticket string `json:"ticket"`;ServerID string `json:"server_id"`;ServerSecret string `json:"server_secret"`};if !readJSON(w,r,&v){return};s.mu.Lock();defer s.mu.Unlock()
 server,ok:=s.db.Servers[v.ServerID];if !ok||!server.Enabled||subtle.ConstantTimeCompare(sha256sum(v.ServerSecret),mustDecode(server.SecretHash))!=1{bad(w,401,"unauthorized server");return}
 claims,e:=s.verifyTicket(v.Ticket,v.ServerID);if e!=nil{bad(w,401,e.Error());return}
 for k,exp:=range s.db.Used{if exp<=s.now().Unix(){delete(s.db.Used,k)}};if _,exists:=s.db.Used[claims.ID];exists{bad(w,409,"ticket already redeemed");return}
 s.db.Used[claims.ID]=claims.Expires;if e=s.saveLocked();e!=nil{bad(w,500,"storage error");return};write(w,200,map[string]any{"subject":claims.Subject,"server_id":claims.Audience,"expires":claims.Expires})
 })
 return withHeaders(mux)
}
func main(){
 listen:=flag.String("listen","127.0.0.1:8088","HTTP listen address (use authenticated HTTPS reverse proxy for remote access)")
 data:=flag.String("data","./data/identity.json","persistent data file, contains signing key");flag.Parse()
 s,e:=newService(*data);if e!=nil{log.Fatal(e)}
 log.Printf("OpenV Identity listening on %s (store %s)",*listen,*data)
 srv:=&http.Server{Addr:*listen,Handler:s.handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:15*time.Second,WriteTimeout:15*time.Second,IdleTimeout:60*time.Second,MaxHeaderBytes:1<<16}
 log.Fatal(srv.ListenAndServe())
}
