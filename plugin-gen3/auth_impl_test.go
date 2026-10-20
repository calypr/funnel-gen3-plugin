package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/tes"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPluginActionUsesUserTokenForGenericS3(t *testing.T) {
	userToken, jwks := signedUserToken(t)
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	var setupAuthorization string
	var exchangedClientToken bool
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "http://fence-service/.well-known/jwks":
			return jsonResponse(req, http.StatusOK, jwks), nil
		case "http://gen3-workflow-service/storage/setup":
			setupAuthorization = req.Header.Get("Authorization")
			return jsonResponse(req, http.StatusOK, `{"bucket":"user-bucket","region":"us-east-1"}`), nil
		case "http://fence-service/oauth2/token?grant_type=client_credentials&scope=openid%20user":
			exchangedClientToken = true
			return jsonResponse(req, http.StatusOK, `{"access_token":"client-token"}`), nil
		default:
			return nil, fmt.Errorf("unexpected auth request to %s", req.URL)
		}
	})

	cfg := config.DefaultConfig()
	resp, err := (Authorize{}).PluginAction(
		map[string]string{
			"S3Url":            "gen3-workflow-service",
			"OidcClientId":     "test-client",
			"OidcClientSecret": "test-secret",
		},
		map[string]*proto.StringList{"authorization": {Values: []string{"Bearer " + userToken}}},
		cfg,
		&tes.Task{Tags: map[string]string{}},
		proto.Type_CREATE,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("plugin response code = %d, message = %q", resp.Code, resp.Message)
	}
	if setupAuthorization != "bearer "+userToken {
		t.Fatal("storage setup did not receive the validated user token")
	}
	if len(resp.Config.GenericS3) != 1 {
		t.Fatalf("GenericS3 backends = %d, want 1", len(resp.Config.GenericS3))
	}
	backend := resp.Config.GenericS3[0]
	if backend.Key != userToken {
		t.Fatal("GenericS3 key must be the validated user token")
	}
	if exchangedClientToken {
		t.Fatal("plugin should not exchange an unused client token")
	}
	if backend.Secret != "N/A" {
		t.Fatalf("GenericS3 secret = %q, want the gateway's ignored placeholder", backend.Secret)
	}
	if backend.Bucket != "user-bucket" || backend.Region != "us-east-1" {
		t.Fatalf("storage setup response was not propagated: bucket=%q region=%q", backend.Bucket, backend.Region)
	}
}

func signedUserToken(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key"})
	claims, _ := json.Marshal(map[string]any{
		"sub":   "test-user",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": []string{"openid"},
	})
	unsigned := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	public := key.PublicKey
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "test-key",
		"alg": "RS256",
		"use": "sig",
		"n":   encode(public.N.Bytes()),
		"e":   encode(big.NewInt(int64(public.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + encode(signature), string(jwks)
}

func jsonResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestPluginActionRejectsInvalidUserTokenBeforeStorageLookup(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	var storageLookup bool
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		storageLookup = true
		return nil, fmt.Errorf("unexpected request to %s", req.URL)
	})

	resp, err := (Authorize{}).PluginAction(
		map[string]string{"S3Url": "gen3-workflow-service", "OidcClientId": "test-client", "OidcClientSecret": "test-secret"},
		map[string]*proto.StringList{"authorization": {Values: []string{"Bearer invalid-token"}}},
		config.DefaultConfig(),
		&tes.Task{Tags: map[string]string{}},
		proto.Type_CREATE,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("plugin response code = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
	if storageLookup {
		t.Fatal("plugin looked up storage for an invalid user token")
	}
}
