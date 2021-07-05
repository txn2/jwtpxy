package jwtpxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
)

type TokenMapping struct {
	Header     string
	TokenKey   string
	TokenValue interface{}
}

func (p *Proxy) ProxyTokenHandler(r *http.Request) error {

	// process JWT
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// WARNING: always validate that the alg is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return p.JWTConfig.PublicKey, nil
	})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		r.Header.Add(StatusHeader, "valid")

		for _, tknMap := range p.TokenMappings {
			if claim, ok := claims[tknMap.TokenKey]; ok {
				if reflect.TypeOf(claim).Kind() == reflect.String {
					r.Header.Add(tknMap.Header, claim.(string))
					r.Header.Add(HeadersHeader, tknMap.Header)
					continue
				}

				claimJson, err := json.Marshal(claim)
				if err != nil {
					p.Logger.Error("unable to marshal claim", zap.Any("tknMap", tknMap), zap.Error(err))
					continue
				}

				r.Header.Add(tknMap.Header, string(claimJson))
				r.Header.Add(HeadersHeader, tknMap.Header)
			}
		}

	} else {
		return errors.New("invalid token")
	}

	return nil
}
