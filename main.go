package main

import (
 "encoding/json"
 "log"
 "net/http"
 "net/url"
 "os"
 "strings"
 "time"

 "github.com/amxv/angelos/internal/app"
 "github.com/amxv/angelos/internal/auth"
 "github.com/amxv/angelos/internal/config"
 "github.com/amxv/angelos/internal/dispatch"
 "github.com/amxv/angelos/internal/mail"
)

func enabled(name string) bool { return os.Getenv(name)=="1" }
func newHandler() http.Handler {
 mux:=http.NewServeMux()
 configured:=false
 unavailable:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("Cache-Control","no-store");http.Error(w,"Angelos is not configured",http.StatusServiceUnavailable)})
 var mcpHandler http.Handler=unavailable
 mailConfig,mailErr:=config.LoadFromEnv()
 authConfig,authErr:=auth.ConfigFromEnv()
 if authErr==nil {
  u,_:=url.Parse(authConfig.ResourceURL)
  if u.Path!="/mcp" {authErr=auth.ErrInvalidToken}
 }
 if authErr==nil {
  gate,e:=auth.New(authConfig)
  if e==nil {
   mux.Handle(auth.MetadataPath,gate.MetadataHandler())
   // RFC 9728 path-specific discovery for a resource ending in /mcp.
   mux.Handle(auth.MetadataPath+"/mcp",gate.MetadataHandler())
   if mailErr==nil {
    backend,e:=mail.New(mailConfig)
    if e==nil {
     a:=&app.App{Mail:backend,Config:mailConfig,EnableWrites:enabled("MAIL_ENABLE_WRITES"),EnableSend:enabled("MAIL_ENABLE_SEND"),EnableDelete:enabled("MAIL_ENABLE_DELETE"),AuthChallenge:gate.Challenge}
     if a.EnableSend {store,e:=dispatch.NewRedis(os.Getenv("ANGELOS_REDIS_REST_URL"),os.Getenv("ANGELOS_REDIS_REST_TOKEN"));if e==nil{a.Store=store}else{a.EnableSend=false;log.Print("send disabled: durable store configuration is incomplete")}}
     mcpHandler=gate.Middleware(a.Handler());configured=true
    }
   }
  }
 }
 if !configured {log.Print("MCP unavailable: mailbox or OAuth configuration is incomplete or invalid")}
 mux.Handle("/mcp",mcpHandler)
 mux.HandleFunc("/healthz",func(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{w.WriteHeader(http.StatusMethodNotAllowed);return};w.Header().Set("Content-Type","application/json");w.Header().Set("Cache-Control","no-store");json.NewEncoder(w).Encode(map[string]any{"service":"angelos","version":"0.1.0","configured":configured})})
 return secureHeaders(mux)
}
func secureHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Cache-Control","no-store");w.Header().Set("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'");if strings.ContainsAny(r.Host,"\r\n"){http.Error(w,"invalid host",400);return};next.ServeHTTP(w,r)})}
func main(){
 port:=os.Getenv("PORT");if port==""{port="8080"}
 server:=&http.Server{Addr:":"+port,Handler:newHandler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:30*time.Second,WriteTimeout:110*time.Second,IdleTimeout:30*time.Second,MaxHeaderBytes:32<<10}
 log.Print("Angelos listening")
 if e:=server.ListenAndServe();e!=nil&&e!=http.ErrServerClosed{log.Fatal("server stopped")}
}
