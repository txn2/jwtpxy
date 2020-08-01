package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/txn2/jwtpxy"

	"github.com/dgrijalva/jwt-go"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	ipEnv               = getEnv("IP", "127.0.0.1")
	portEnv             = getEnv("PORT", "8080")
	utilPortEnv         = getEnv("UTIL_PORT", "8000")
	metricsPortEnv      = getEnv("METRICS_PORT", "2112")
	readTimeoutEnv      = getEnv("READ_TIMEOUT", "10")
	writeTimeoutEnv     = getEnv("WRITE_TIMEOUT", "10")
	debugEnv            = getEnv("DEBUG", "false")
	keycloakEnv         = getEnv("KEYCLOAK", "http://localhost:8090/auth/realms/master")
	backendEnv          = getEnv("BACKEND", "http://localhost:8000")
	headerMappingsEnv   = getEnv("HEADER_MAPPING", "From:preferred_username,Realm-Access:realm_access")
	requireTokenModeEnv = getEnv("REQUIRE_TOKEN", "true")
	sigHeaderEnv        = getEnv("SIG_HEADER", "shared_secret_change_me")
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
		log.Fatal("Parsing error, readTimeout must be an integer in seconds.")
	}

	writeTimeoutInt, err := strconv.Atoi(writeTimeoutEnv)
	if err != nil {
		log.Fatal("Parsing error, readTimeout must be an integer in seconds.")
	}

	var (
		ip               = flag.String("ip", ipEnv, "Server IP address to bind to.")
		port             = flag.String("port", portEnv, "Server port.")
		utilPort         = flag.String("utilPort", utilPortEnv, "Utility server port.")
		metricsPort      = flag.String("metricsPort", metricsPortEnv, "Metrics port.")
		readTimeout      = flag.Int("readTimeout", readTimeoutInt, "HTTP read timeout")
		writeTimeout     = flag.Int("writeTimeout", writeTimeoutInt, "HTTP write timeout")
		keycloak         = flag.String("keycloak", keycloakEnv, "Keycloak realm info")
		backend          = flag.String("backend", backendEnv, "Backend service")
		debug            = flag.String("debug", debugEnv, "Debug log level")
		sigHeader        = flag.String("sigHeader", sigHeaderEnv, "Signature header / shared secret")
		requireTokenMode = flag.String("requireTokenMode", requireTokenModeEnv, "set to string \"false\" to allow un-authenticated pass-through.")
		headerMappings   = flag.String("headerMappings", headerMappingsEnv, "Mapping HTTPS headers to token attributes.")
	)
	flag.Parse()

	tknMappings := make([]jwtpxy.TokenMapping, 0)

	// create map of headers to token attributes
	var mappingSplit = strings.Split(*headerMappings, ",")
	for _, mapping := range mappingSplit {
		kvSplit := strings.Split(mapping, ":")

		if len(kvSplit) == 2 {
			tknMappings = append(tknMappings, jwtpxy.TokenMapping{
				Header:   kvSplit[0],
				TokenKey: kvSplit[1],
			})
		}
	}

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
		logger.Fatal("Unable to create request to populate certificate", zap.Error(err))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Fatal("Unable to get realm information", zap.Error(err))
	}

	if resp.StatusCode != http.StatusOK {
		logger.Fatal("Keycloak returned non-200 response", zap.Int("code", resp.StatusCode))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Fatal("Unable read response body from Keycloak", zap.Error(err))
	}

	realmInfo := RealmInfo{}

	err = json.Unmarshal(body, &realmInfo)
	if err != nil {
		logger.Fatal("Unable to unmarshal realm information", zap.Error(err))
	}

	// make pem
	pem := "-----BEGIN PUBLIC KEY-----\n" + realmInfo.PublicKey + "\n-----END PUBLIC KEY-----"
	rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		logger.Fatal("Unable to ParseRSAPublicKeyFromPEM", zap.Error(err))
	}

	// Backend Configuration
	targetUrl, err := url.Parse(*backend)
	if err != nil {
		logger.Fatal("Unable to parse backend URL", zap.Error(err))
	}

	pxy := httputil.NewSingleHostReverseProxy(targetUrl)

	pmx := &jwtpxy.Pmx{
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
	jwtConfig := jwtpxy.JWTConfig{
		PublicKey: rsaPublicKey,
	}

	// Proxy
	proxy := &jwtpxy.Proxy{
		Target:           targetUrl,
		Proxy:            pxy,
		Logger:           logger,
		JWTConfig:        jwtConfig,
		Pmx:              pmx,
		RequireTokenMode: *requireTokenMode,
		TokenMappings:    tknMappings,
		SigHeader:        *sigHeader,
	}

	// proxy mux
	pMux := http.NewServeMux()

	// handlers / middleware
	pMux.HandleFunc("/", use(proxy.Handle))

	// Proxy Server
	pxySrv := &http.Server{
		Addr:         *ip + ":" + *port,
		Handler:      pMux,
		ReadTimeout:  time.Duration(*readTimeout) * time.Second,
		WriteTimeout: time.Duration(*writeTimeout) * time.Second,
	}

	// util mux
	uMux := http.NewServeMux()

	// handlers / middleware
	uMux.HandleFunc("/", utilHandler)

	// Proxy Server
	uSrv := &http.Server{
		Addr:         *ip + ":" + *utilPort,
		Handler:      uMux,
		ReadTimeout:  time.Duration(*readTimeout) * time.Second,
		WriteTimeout: time.Duration(*writeTimeout) * time.Second,
	}

	// metrics server (run in go routine)
	go func() {
		http.Handle("/metrics", promhttp.Handler())

		logger.Info("Starting jwtpxy Metrics Server",
			zap.String("type", "metrics_startup"),
			zap.String("version", Version),
			zap.String("port", *metricsPort),
			zap.String("ip", *ip),
		)

		err = http.ListenAndServe(*ip+":"+*metricsPort, nil)
		if err != nil {
			logger.Fatal("Error Starting Score API Metrics Server", zap.Error(err))
			os.Exit(1)
		}
	}()

	logger.Info("Starting the jwtpxy Utility Server",
		zap.String("port", *utilPort),
		zap.String("version", Version),
		zap.String("ip", *ip),
	)

	// start util server (run in go routine)
	go func() {
		err = uSrv.ListenAndServe()
		if err != nil {
			logger.Fatal("Error starting utility server", zap.Error(err))
		}
	}()

	logger.Info("Starting the jwtpxy Reverse Proxy",
		zap.String("port", *port),
		zap.String("ip", *ip),
		zap.String("version", Version),
		zap.String("backend", *backend),
	)

	// start proxy server
	err = pxySrv.ListenAndServe()
	if err != nil {
		logger.Fatal("Error starting proxy server", zap.Error(err))
	}
	os.Exit(0)
}

// requestDebug
type requestDebug struct {
	HttpHeader http.Header `json:"http_header"`
	Token      debugToken  `json:"token"`
}

// debugToken
type debugToken struct {
	Header    tokenElm `json:"header,omitempty"`
	Data      tokenElm `json:"data,omitempty"`
	Signature string   `json:"signature,omitempty"`
}

type tokenElm map[string]interface{}

// utilHandler
// Utility service may be used for default backend when testing.
func utilHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rd := requestDebug{
		HttpHeader: r.Header,
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	var tokenSplits = strings.Split(tokenString, ".")

	if len(tokenSplits) == 3 {
		tokenSig := tokenSplits[2]
		rd.Token = debugToken{
			Signature: tokenSig,
		}

		tokenHeader, err := base64.RawStdEncoding.DecodeString(tokenSplits[0])

		if err == nil {
			header := &tokenElm{}
			err := json.Unmarshal(tokenHeader, header)
			if err != nil {
				log.Print(err.Error())
			}
			rd.Token.Header = *header
		}

		tokenData, err := base64.RawStdEncoding.DecodeString(tokenSplits[1])
		if err == nil {
			data := &tokenElm{}
			if json.Unmarshal(tokenData, data) == nil {
				rd.Token.Data = *data
			}
		}

	}

	js, err := json.MarshalIndent(rd, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(js)
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
