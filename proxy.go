package jwtpxy

import (
	"crypto/rsa"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const HeadersHeader = "JwtPxy-Headers"
const StatusHeader = "JwtPxy-Token-Status"
const RequireTokenModeHeader = "JwtPxy-Require-Token-Mode"
const SignatureHeader = "JwtPxy-Signature"

type Proxy struct {
	Target           *url.URL
	Proxy            *httputil.ReverseProxy
	Logger           *zap.Logger
	JWTConfig        JWTConfig
	Pmx              *Pmx
	RequireTokenMode string
	SigHeader        string
	TokenMappings    []TokenMapping
	AllowCookieToken string
	CookieTokenName  string
}

type JWTConfig struct {
	PublicKey *rsa.PublicKey `json:"public_key"`
}

type Pmx struct {
	Requests  prometheus.Counter
	Latency   prometheus.Summary
	AuthFails prometheus.Counter
}

func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) {

	var admit = true

	p.Pmx.Requests.Inc()

	requireTokenMode := "true"
	if p.RequireTokenMode == "false" {
		requireTokenMode = "false"
	}

	// prep headers: remove used headers to prevent existing value
	// from leaking through
	for _, tknMap := range p.TokenMappings {
		r.Header.Del(tknMap.Header)
	}

	r.Header.Del(StatusHeader)
	r.Header.Del(HeadersHeader)
	r.Header.Del(RequireTokenModeHeader)
	r.Header.Del(SignatureHeader)

	r.Header.Add(HeadersHeader, HeadersHeader)
	r.Header.Add(HeadersHeader, StatusHeader)
	r.Header.Add(HeadersHeader, RequireTokenModeHeader)
	r.Header.Add(HeadersHeader, SignatureHeader)

	r.Header.Add(SignatureHeader, p.SigHeader)
	r.Header.Add(RequireTokenModeHeader, requireTokenMode)

	start := time.Now()
	reqPath := r.URL.Path
	reqMethod := r.Method
	r.Host = p.Target.Host

	// if there is a token we must process it, if there is
	// not a token we check requireTokenMode for "false"
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// if Bearer token is empty and cookie token is true.
	if tokenString != "" && p.AllowCookieToken == "true" {
		tokenCookie, _ := r.Cookie(p.CookieTokenName)
		if tokenCookie != nil && tokenCookie.Secure && tokenCookie.HttpOnly {
			tokenString = tokenCookie.String()
		}
	}

	if tokenString != "" {
		err := p.ProxyTokenHandler(r, tokenString)
		if err != nil {
			// fail
			admit = false

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			_, _ = w.Write([]byte("{\"status\": \"" + strings.ToLower(err.Error()) + "\"}"))
		}
	}

	// is requireTokenMode is true then a token is required
	// return unauthorized
	if admit && tokenString == "" && requireTokenMode == "true" {
		// fail
		admit = false

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		_, _ = w.Write([]byte("{\"status\": \"missing required token\"}"))
	}

	// serve backend
	if admit == true {
		p.Proxy.ServeHTTP(w, r)
	}

	end := time.Now()
	latency := end.Sub(start)
	p.Pmx.Latency.Observe(float64(latency))

	p.Logger.Debug(reqPath,
		zap.String("method", reqMethod),
		zap.String("path", reqPath),
		zap.String("time", end.Format(time.RFC3339)),
		zap.Duration("latency", latency),
		zap.Bool("admit", admit),
		zap.Any("header", r.Header),
		zap.String("token", tokenString),
	)
}
