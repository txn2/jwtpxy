package main

import (
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	ipEnv           = getEnv("IP", "127.0.0.1")
	portEnv         = getEnv("PORT", "8080")
	metricsPortEnv  = getEnv("METRICS_PORT", "2112")
	readTimeoutEnv  = getEnv("READ_TIMEOUT", "10")
	writeTimeoutEnv = getEnv("WRITE_TIMEOUT", "10")
	debugEnv        = getEnv("DEBUG", "false")
	keycloakEnv     = getEnv("KEYCLOAK", "http://web-keycloak:8080/auth/realms/master")
	backendEnv      = getEnv("BACKEND", "http://api:80")
)

var Version = "0.0.0"

// Realm info from Keycloak
type RealmInfo struct {
	Realm           string `json:"realm"`
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

// JWTConfig
type JWTConfig struct {
	PublicKey *rsa.PublicKey `json:"public_key"`
}

// Proxy
type Proxy struct {
	Target    *url.URL
	Proxy     *httputil.ReverseProxy
	Logger    *zap.Logger
	JWTConfig JWTConfig
	Pmx       *Pmx
}

// Pmx
type Pmx struct {
	Requests  prometheus.Counter
	Latency   prometheus.Summary
	AuthFails prometheus.Counter
}

// handle requests
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {

	p.Pmx.Requests.Inc()

	start := time.Now()
	reqPath := r.URL.Path
	reqMethod := r.Method
	r.Host = p.Target.Host

	// get JWT token
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Missing token"))
		return
	}

	// process JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return p.JWTConfig.PublicKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// @TODO map claims to headers from config
		// @TODO config headers to preserve
		r.Header = http.Header{}
		r.Header.Add("From", claims["preferred_username"].(string))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Invalid token claims"))
		return
	}

	p.Proxy.ServeHTTP(w, r)

	end := time.Now()
	latency := end.Sub(start)
	p.Pmx.Latency.Observe(float64(latency))

	p.Logger.Debug(reqPath,
		zap.String("method", reqMethod),
		zap.String("path", reqPath),
		zap.String("time", end.Format(time.RFC3339)),
		zap.Duration("latency", latency),
	)
}

// use - middleware shim
func use(h http.HandlerFunc, middleware ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for _, m := range middleware {
		h = m(h)
	}

	return h
}

func main() {
	readTimeoutInt, err := strconv.Atoi(readTimeoutEnv)
	if err != nil {
		fmt.Println("Parsing error, readTimeout must be an integer in seconds.")
		os.Exit(1)
	}

	writeTimeoutInt, err := strconv.Atoi(writeTimeoutEnv)
	if err != nil {
		fmt.Println("Parsing error, readTimeout must be an integer in seconds.")
		os.Exit(1)
	}

	var (
		ip           = flag.String("ip", ipEnv, "Server IP address to bind to.")
		port         = flag.String("port", portEnv, "Server port.")
		metricsPort  = flag.String("metricsPort", metricsPortEnv, "Metrics port.")
		readTimeout  = flag.Int("readTimeout", readTimeoutInt, "HTTP read timeout")
		writeTimeout = flag.Int("writeTimeout", writeTimeoutInt, "HTTP write timeout")
		keycloak     = flag.String("keycloak", keycloakEnv, "Keycloak realm info")
		backend      = flag.String("backend", backendEnv, "Backend service")
		debug        = flag.String("debug", debugEnv, "Debug log level")
	)
	flag.Parse()

	// Logging
	zapCfg := zap.NewProductionConfig()

	if *debug == "true" {
		zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	logger, err := zapCfg.Build()
	if err != nil {
		fmt.Printf("Cannot build logger: %s\n", err.Error())
		os.Exit(1)
	}

	// HTTP Client for certificate retrieval
	netTransport := &http.Transport{
		MaxIdleConnsPerHost: 10,
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   time.Second * 60,
		Transport: netTransport,
	}

	// Populate public certificate
	req, err := http.NewRequest("GET", *keycloak, nil)
	if err != nil {
		logger.Error("Unable to create request to populate certificate", zap.Error(err))
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("Unable to get realm information", zap.Error(err))
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error("Keycloak returned non-200 response", zap.Int("code", resp.StatusCode))
		os.Exit(1)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Unable read response body from Keycloak", zap.Error(err))
		os.Exit(1)
	}

	realmInfo := RealmInfo{}

	err = json.Unmarshal(body, &realmInfo)
	if err != nil {
		logger.Error("Unable to unmarshal realm information", zap.Error(err))
		os.Exit(1)
	}

	// make pem
	pem := "-----BEGIN PUBLIC KEY-----\n" + realmInfo.PublicKey + "\n-----END PUBLIC KEY-----"
	rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		logger.Error("Unable to ParseRSAPublicKeyFromPEM", zap.Error(err))
		os.Exit(1)
	}

	// Backend Configuration
	targetUrl, err := url.Parse(*backend)
	if err != nil {
		logger.Error("Unable to parse URL", zap.Error(err))
		os.Exit(1)
	}

	pxy := httputil.NewSingleHostReverseProxy(targetUrl)

	pmx := &Pmx{
		Requests: promauto.NewCounter(prometheus.CounterOpts{
			Name: "jwtpxy_total_requests",
			Help: "Total number of requests received.",
		}),

		Latency: promauto.NewSummary(prometheus.SummaryOpts{
			Name: "jwtpxy_response_time",
			Help: "Response latency.",
		}),
	}

	// JWTConfig
	jwtConfig := JWTConfig{
		PublicKey: rsaPublicKey,
	}

	// Proxy
	proxy := &Proxy{
		Target:    targetUrl,
		Proxy:     pxy,
		Logger:    logger,
		JWTConfig: jwtConfig,
		Pmx:       pmx,
	}

	mux := http.NewServeMux()

	// handlers / middleware
	mux.HandleFunc("/", use(proxy.handle))

	// HTTP Server
	srv := &http.Server{
		Addr:         *ip + ":" + *port,
		Handler:      mux,
		ReadTimeout:  time.Duration(*readTimeout) * time.Second,
		WriteTimeout: time.Duration(*writeTimeout) * time.Second,
	}

	// metrics server (run in go routine)
	go func() {
		http.Handle("/metrics", promhttp.Handler())

		logger.Info("Starting jwtpxy Metrics Server",
			zap.String("type", "metrics_startup"),
			zap.String("port", *metricsPort),
			zap.String("ip", *ip),
		)

		err = http.ListenAndServe(*ip+":"+*metricsPort, nil)
		if err != nil {
			logger.Fatal("Error Starting Score API Metrics Server", zap.Error(err))
			os.Exit(1)
		}
	}()

	logger.Info("Starting the jwtpxy Reverse Proxy",
		zap.String("port", *port),
		zap.String("ip", *ip),
		zap.String("backend", *backend),
	)

	err = srv.ListenAndServe()
	if err != nil {
		fmt.Printf("Error starting Proxy: %s\n", err.Error())
	}
	os.Exit(0)
}

// getEnv gets an environment variable or sets a default if
// one does not exist.
func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}

	return value
}
