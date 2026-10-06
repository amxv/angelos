package mail

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "io"
 "net"
 "net/netip"
 "strconv"
 "sync"
 "time"

 "github.com/amxv/angelos/internal/config"
 "github.com/emersion/go-imap/v2"
 "github.com/emersion/go-imap/v2/imapclient"
)

const maxWireBytes int64 = 12 << 20

type Backend struct {
 config config.Config
 // Private test seams. Production always resolves and vets all DNS answers,
 // then dials the numeric address, so there is no second DNS lookup to rebind.
 dialContext func(context.Context,string,string)(net.Conn,error)
 lookupIP func(context.Context,string,string)([]net.IP,error)
 roots *x509.CertPool
}
func New(c config.Config) (*Backend,error) {if err:=c.Validate();err!=nil{return nil,err};return &Backend{config:c},nil}

type boundedConn struct {net.Conn; deadline time.Time; remaining int64; mu sync.Mutex}
func (c *boundedConn) clamp(t time.Time) time.Time {if t.IsZero()||t.After(c.deadline){return c.deadline};return t}
func (c *boundedConn) SetDeadline(t time.Time) error {return c.Conn.SetDeadline(c.clamp(t))}
func (c *boundedConn) SetReadDeadline(t time.Time) error {return c.Conn.SetReadDeadline(c.clamp(t))}
func (c *boundedConn) SetWriteDeadline(t time.Time) error {return c.Conn.SetWriteDeadline(c.clamp(t))}
func (c *boundedConn) Read(p []byte)(int,error) {
 c.mu.Lock();defer c.mu.Unlock()
 if c.remaining<=0 {return 0,ErrLimit};if int64(len(p))>c.remaining {p=p[:int(c.remaining)]}
 n,e:=c.Conn.Read(p);c.remaining-=int64(n);return n,e
}

var forbiddenV4=[]netip.Prefix{
 netip.MustParsePrefix("0.0.0.0/8"),netip.MustParsePrefix("10.0.0.0/8"),netip.MustParsePrefix("100.64.0.0/10"),netip.MustParsePrefix("127.0.0.0/8"),netip.MustParsePrefix("169.254.0.0/16"),netip.MustParsePrefix("172.16.0.0/12"),netip.MustParsePrefix("192.0.0.0/24"),netip.MustParsePrefix("192.0.2.0/24"),netip.MustParsePrefix("192.88.99.0/24"),netip.MustParsePrefix("192.168.0.0/16"),netip.MustParsePrefix("198.18.0.0/15"),netip.MustParsePrefix("198.51.100.0/24"),netip.MustParsePrefix("203.0.113.0/24"),netip.MustParsePrefix("224.0.0.0/3"),
}
var forbiddenV6=[]netip.Prefix{netip.MustParsePrefix("2001::/23"),netip.MustParsePrefix("2001:db8::/32"),netip.MustParsePrefix("2002::/16"),netip.MustParsePrefix("3fff::/20")}
func publicIP(ip net.IP) bool {
 a,ok:=netip.AddrFromSlice(ip);if !ok{return false};a=a.Unmap()
 if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast(){return false}
 if a.Is4(){for _,p:=range forbiddenV4 {if p.Contains(a){return false}};return true}
 if !netip.MustParsePrefix("2000::/3").Contains(a){return false}
 for _,p:=range forbiddenV6{if p.Contains(a){return false}};return true
}
func (b *Backend) dial(ctx context.Context, ep config.Endpoint)(net.Conn,error) {
 if b.dialContext!=nil {return b.dialContext(ctx,"tcp",net.JoinHostPort(ep.Host,strconv.Itoa(ep.Port)))}
 lookup:=b.lookupIP;if lookup==nil{lookup=net.DefaultResolver.LookupIP}
 ips,err:=lookup(ctx,"ip",ep.Host);if err!=nil||len(ips)==0{return nil,ErrUnavailable}
 for _,ip:=range ips {if !publicIP(ip){return nil,ErrUnavailable}}
 var last error
 for _,ip:=range ips {
  conn,err:=(&net.Dialer{}).DialContext(ctx,"tcp",net.JoinHostPort(ip.String(),strconv.Itoa(ep.Port)))
  if err==nil{return conn,nil};last=err
 }
 return nil,last
}
func (b *Backend) openConn(ctx context.Context,ep config.Endpoint)(net.Conn,func(),error) {
 ctx,cancel:=context.WithTimeout(ctx,b.config.Timeout)
 conn,err:=b.dial(ctx,ep);if err!=nil{cancel();return nil,nil,ErrUnavailable}
 deadline,_:=ctx.Deadline()
 conn=&boundedConn{Conn:conn,deadline:deadline,remaining:maxWireBytes}
 if err:=conn.SetDeadline(deadline);err!=nil{conn.Close();cancel();return nil,nil,ErrUnavailable}
 stop:=context.AfterFunc(ctx,func(){conn.Close()})
 done:=func(){stop();conn.Close();cancel()}
 return conn,done,nil
}
func (b *Backend) tlsConfig(host string)*tls.Config {return &tls.Config{ServerName:host,MinVersion:tls.VersionTLS12,RootCAs:b.roots}}

type imapSession struct {client *imapclient.Client; cleanup func()}
func (s *imapSession) close(){s.client.Close();s.cleanup()}
func (b *Backend) connectIMAP(ctx context.Context)(*imapSession,error) {
 conn,done,err:=b.openConn(ctx,b.config.IMAP);if err!=nil{return nil,err}
 secure:=tls.Client(conn,b.tlsConfig(b.config.IMAP.Host))
 if err:=secure.HandshakeContext(ctx);err!=nil{done();return nil,ErrUnavailable}
 client:=imapclient.New(secure,nil)
 if err:=client.WaitGreeting();err!=nil {client.Close();done();return nil,ErrUnavailable}
 if err:=client.Login(b.config.Username,b.config.Password).Wait();err!=nil {client.Close();done();return nil,ErrUnavailable}
 return &imapSession{client:client,cleanup:done},nil
}
func (s *imapSession) selectMailbox(folder string, uidValidity uint32)(*imap.SelectData,error) {
 if !validFolder(folder){return nil,ErrInvalidInput}
 data,err:=s.client.Select(folder,&imap.SelectOptions{ReadOnly:true}).Wait()
 if err!=nil{return nil,ErrUnavailable}
 if data.UIDValidity==0 || data.UIDNext==0 {return nil,ErrUnavailable}
 if uidValidity!=0&&data.UIDValidity!=uidValidity{return nil,ErrStaleReference}
 return data,nil
}
// Do not leak provider response text, mailbox contents, or credentials in errors.
func safeError(err error)error {
 if err==nil{return nil}
 for _,e:=range []error{ErrInvalidInput,ErrStaleReference,ErrNotFound,ErrLimit,ErrUnsupported,ErrConflict,ErrOutcomeUnknown,context.Canceled,context.DeadlineExceeded}{if errors.Is(err,e){return e}}
 if errors.Is(err,io.EOF){return ErrUnavailable};return ErrUnavailable
}
