package main

import (
    "crypto/ed25519"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/bradjtrammell/openv-identity/pkg/ticket"
)

func TestV2IssuingLoginRevocationAndLivenessAcrossRestart(t *testing.T) {
    t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-bootstrap-secret-for-session-bound-admission")
    path := filepath.Join(t.TempDir(), "identity.json")
    s, err := newService(path)
    if err != nil { t.Fatal(err) }
    h := s.handler()
    api(t,h,"POST","/api/v1/bootstrap","",map[string]string{
        "username":"admin","password":"long-admin-password-for-v2","bootstrap_secret":"test-bootstrap-secret-for-session-bound-admission",
    },201)
    first := api(t,h,"POST","/api/v1/auth/login","",map[string]string{
        "username":"admin","password":"long-admin-password-for-v2",
    },200)["access_token"].(string)
    server := api(t,h,"POST","/api/v1/servers/register",first,map[string]string{
        "name":"Admission test","address":"127.0.0.1:30120",
    },201)
    id, secret := server["id"].(string),server["server_secret"].(string)
    issue := func(token string) string {
        return api(t,h,"POST","/api/v1/tickets",token,map[string]string{"server_id":id},200)["ticket"].(string)
    }
    redeem := func(value string,want int) map[string]any {
        return api(t,h,"POST","/api/v1/tickets/redeem","",map[string]string{
            "ticket":value,"server_id":id,"server_secret":secret,
        },want)
    }
    firstTicket := issue(first)
    if !strings.HasPrefix(firstTicket,"ov2.") { t.Fatal("new tickets must be session-bound ov2") }
    claims,err := ticket.Verify(firstTicket,id,s.signer.Public().(ed25519.PublicKey),time.Now())
    if err != nil { t.Fatal(err) }
    sid := b64(sha256sum(first))
    if claims.Version != 2 || claims.Session != sid { t.Fatalf("unbound ticket: %+v",claims) }
    second := api(t,h,"POST","/api/v1/auth/login","",map[string]string{
        "username":"admin","password":"long-admin-password-for-v2",
    },200)["access_token"].(string)
    if second == first { t.Fatal("login capability reused") }
    check := func(want bool) {
        response := api(t,h,"POST","/api/v1/sessions/check","",map[string]any{
            "server_id":id,"server_secret":secret,
            "sessions":[]map[string]string{
                {"subject":claims.Subject,"login_session":sid},
                {"subject":"unrelated-subject","login_session":sid},
            },
        },200)
        active := response["active"].([]any)
        if len(active)!=2 || active[0]!=want || active[1]!=false { t.Fatalf("unexpected liveness: %v",active) }
    }
    check(true)
    api(t,h,"POST","/api/v1/auth/logout",first,nil,200)
    check(false)
    s,err = newService(path)
    if err != nil { t.Fatal(err) }
    h=s.handler()
    redeem(firstTicket,401)
    check(false)
    secondTicket:=issue(second)
    result:=redeem(secondTicket,200)
    if result["login_session"]!=b64(sha256sum(second)) || result["subject"]!=claims.Subject {
        t.Fatalf("incorrect redeemed login binding: %v",result)
    }
    redeem(secondTicket,409)
    if len(s.db.Used)!=1 { t.Fatalf("revoked ticket poisoned replay state: %+v",s.db.Used) }
}

func TestV2LivenessRequiresRegisteredServerAndBoundedCanonicalBatch(t *testing.T) {
    s,err:=newService(filepath.Join(t.TempDir(),"identity.json"))
    if err!=nil { t.Fatal(err) }
    h:=s.handler()
    sid:=b64(make([]byte,32))
    item:=map[string]string{"subject":"subject-123","login_session":sid}
    request:=map[string]any{
        "server_id":"not-registered","server_secret":"wrong",
        "sessions":[]map[string]string{item},
    }
    api(t,h,"POST","/api/v1/sessions/check","",request,401)
    for _,sessions:=range [][]map[string]string{
        {},
        {{"subject":"subject-123","login_session":"!"}},
        {{"subject":"x","login_session":sid}},
        {{"subject":"subject-123","login_session":sid+"="}},
    } {
        request["sessions"]=sessions
        api(t,h,"POST","/api/v1/sessions/check","",request,400)
    }
    many:=make([]map[string]string,maxLivenessBatch+1)
    for i:=range many { many[i]=item }
    request["sessions"]=many
    api(t,h,"POST","/api/v1/sessions/check","",request,400)
}

func TestV2TicketCannotRedeemAfterLoginExpiry(t *testing.T) {
    t.Setenv("OPENV_BOOTSTRAP_SECRET", "test-bootstrap-secret-for-expiring-v2")
    s,err:=newService(filepath.Join(t.TempDir(),"identity.json"))
    if err!=nil { t.Fatal(err) }
    h:=s.handler()
    api(t,h,"POST","/api/v1/bootstrap","",map[string]string{
        "username":"admin","password":"long-password-for-expiring-v2","bootstrap_secret":"test-bootstrap-secret-for-expiring-v2",
    },201)
    login:=api(t,h,"POST","/api/v1/auth/login","",map[string]string{
        "username":"admin","password":"long-password-for-expiring-v2",
    },200)["access_token"].(string)
    server:=api(t,h,"POST","/api/v1/servers/register",login,map[string]string{
        "name":"Expiry test","address":"127.0.0.1:30120",
    },201)
    id,secret:=server["id"].(string),server["server_secret"].(string)
    issued:=api(t,h,"POST","/api/v1/tickets",login,map[string]string{"server_id":id},200)["ticket"].(string)
    key:=b64(sha256sum(login))
    s.mu.Lock()
    session:=s.db.Sessions[key]
    session.Expires=s.now().Unix()-1
    s.db.Sessions[key]=session
    s.mu.Unlock()
    api(t,h,"POST","/api/v1/tickets/redeem","",map[string]string{
        "ticket":issued,"server_id":id,"server_secret":secret,
    },401)
    if len(s.db.Used)!=0 { t.Fatal("expired login consumed replay nonce") }
}
