package dispatch

import (
 "bufio"
 "context"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "strconv"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/amxv/angelos/internal/compose"
)

// CI uses an ephemeral local Redis container, never an operator's Redis account.
// This minimal RESP bridge exercises the exact REST EVAL scripts against Redis.
func redisFixture(t *testing.T)*Redis{
 t.Helper();addr:=os.Getenv("ANGELOS_TEST_REDIS_ADDR");if addr==""{t.Skip("ephemeral Redis fixture not configured")}
 if !strings.HasPrefix(addr,"127.0.0.1:"){t.Fatal("test Redis must be loopback")}
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  var cmd []any;if json.NewDecoder(io.LimitReader(r.Body,24<<20)).Decode(&cmd)!=nil{http.Error(w,"bad JSON",400);return}
  c,e:=net.DialTimeout("tcp",addr,2*time.Second);if e!=nil{http.Error(w,"fixture unavailable",503);return};defer c.Close();c.SetDeadline(time.Now().Add(5*time.Second));fmt.Fprintf(c,"*%d\r\n",len(cmd));for _,arg:=range cmd{s:=fmt.Sprint(arg);fmt.Fprintf(c,"$%d\r\n%s\r\n",len(s),s)}
  v,e:=readRESP(bufio.NewReader(c));if e!=nil{json.NewEncoder(w).Encode(map[string]any{"error":e.Error()});return};json.NewEncoder(w).Encode(map[string]any{"result":v})
 }));t.Cleanup(srv.Close)
 return &Redis{endpoint:srv.URL,token:"fixture-only",client:srv.Client()}
}
func readRESP(r *bufio.Reader)(any,error){line,e:=r.ReadString('\n');if e!=nil{return nil,e};if len(line)<3{return nil,fmt.Errorf("bad RESP")};body:=strings.TrimSuffix(line[1:],"\r\n");switch line[0]{case '+':return body,nil;case '-':return nil,fmt.Errorf("Redis fixture error: %s",body);case ':':return strconv.Atoi(body);case '$':n,e:=strconv.Atoi(body);if e!=nil||n>24<<20{return nil,fmt.Errorf("bad bulk")};if n<0{return nil,nil};b:=make([]byte,n+2);_,e=io.ReadFull(r,b);return string(b[:n]),e;case '*':n,e:=strconv.Atoi(body);if e!=nil||n>100{return nil,fmt.Errorf("bad array")};v:=make([]any,n);for i:=range v{v[i],e=readRESP(r);if e!=nil{return nil,e}};return v,nil};return nil,fmt.Errorf("unknown RESP")}
func TestRedisAtomicClaimAndRetention(t *testing.T){
 r:=redisFixture(t);p,e:=compose.Build("sender@example.com",compose.Input{To:[]string{"to@example.com"},Bcc:[]string{"private@example.com"},Text:"CONFIDENTIAL_FIXTURE"},"00000000000000000000000000000001",time.Now());if e!=nil{t.Fatal(e)}
 ctx:=context.Background();if e=r.Put(ctx,p);e!=nil{t.Fatal(e)};if _,_,e=r.Claim(ctx,p.ID,strings.Repeat("a",64),time.Now());e==nil{t.Fatal("digest mismatch accepted")}
 var claims atomic.Int32;var wg sync.WaitGroup
 for i:=0;i<16;i++{wg.Add(1);go func(){defer wg.Done();rec,ok,e:=r.Claim(ctx,p.ID,p.Digest,time.Now());if e!=nil{t.Error(e);return};if ok{claims.Add(1);if string(rec.Message.Raw)!=string(p.Raw){t.Error("original payload lost before dispatch")}}}()};wg.Wait();if claims.Load()!=1{t.Fatalf("got %d claims",claims.Load())}
 k,_:=key(p.ID);raw,e:=r.command(ctx,"GET",k);if e!=nil{t.Fatal(e)};for _,secret:=range []string{"CONFIDENTIAL_FIXTURE","private@example.com","to@example.com","raw","recipients"}{if strings.Contains(string(raw),secret){t.Fatalf("consumed payload retained %q",secret)}}
 if e=r.Complete(ctx,p.ID,"accepted","acknowledgement");e!=nil{t.Fatal(e)};rec,ok,e:=r.Claim(ctx,p.ID,p.Digest,time.Now());if e!=nil||ok||rec.Status!="accepted"{t.Fatalf("duplicate replay %v %v %s",e,ok,rec.Status)}
 ttl,e:=r.command(ctx,"TTL",k);if e!=nil{t.Fatal(e)};var seconds int;json.Unmarshal(ttl,&seconds);if seconds<604790||seconds>604800{t.Fatal("missing durable consumed marker",seconds)}
}
func TestRedisExpiredPreparationNotClaimed(t *testing.T){r:=redisFixture(t);p,e:=compose.Build("sender@example.com",compose.Input{To:[]string{"to@example.com"}},"00000000000000000000000000000002",time.Now().Add(-time.Hour));if e!=nil{t.Fatal(e)};if e=r.Put(context.Background(),p);e!=nil{t.Fatal(e)};if _,_,e=r.Claim(context.Background(),p.ID,p.Digest,time.Now());e==nil{t.Fatal("expired preparation accepted")}}
