package main

import (
	"aidanwoods.dev/go-paseto"
	"context"
	"github.com/itsabgr/fak"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/crypto/sha3"
	"io"
	"mauth"
	"mauth/providers"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func urlWithQuery(url *url.URL, k, v string) {
	q := url.Query()
	q.Set(k, v)
	url.RawQuery = q.Encode()
}

func main() {
	configPath := os.Getenv("MAUTH_CONFIG_PATH")
	redirectURI := os.Getenv("MAUTH_REDIRECT_URI")
	listenAddr := os.Getenv("MAUTH_LISTEN_ADDR")
	secretPath := os.Getenv("MAUTH_SECRET_PATH")

	secretSeed := fak.Must(os.ReadFile(secretPath))
	secretBytes := sha3.Sum256(secretSeed)
	secret := fak.Must(paseto.V4SymmetricKeyFromBytes(secretBytes[:]))

	fak.Throw(ParseConfig(configPath))
	fak.Throw(config.Providers.InitProviders(providers.Map, redirectURI))

	authenticator := mauth.NewAuthenticator(providers.Map, secret)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		token, err := paseto.NewParser().ParseV4Local(secret, request.URL.Query().Get("code"), nil)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusUnauthorized)
			return
		}
		emails, _ := token.GetString("emails")
		io.WriteString(writer, emails)
	})
	mux.HandleFunc("/resolve", func(writer http.ResponseWriter, request *http.Request) {
		token, err := paseto.NewParser().ParseV4Local(secret, request.Header.Get("Authorization"), nil)
		if err != nil {
			http.Error(writer, "auth failed", http.StatusUnauthorized)
			return
		}
		emails, _ := token.GetString("emails")
		io.WriteString(writer, emails)
	})

	mux.HandleFunc("/auth", func(writer http.ResponseWriter, request *http.Request) {
		redirect, err := url.Parse(request.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(writer, "invalid redirect_uri", http.StatusBadRequest)
			return
		}

		a, err := authenticator.NewAuthentication(*redirect)
		if err != nil {
			http.Error(writer, "failed", http.StatusBadRequest)
			return
		}
		_ = mauth.RenderLoginTemplate(writer, mauth.LoginTemplateArgs{
			Authentication: a,
		})
	})

	mux.HandleFunc("/cb", func(writer http.ResponseWriter, request *http.Request) {
		state := &mauth.State{}
		err := state.Decrypt(request.URL.Query().Get("state"), secret)
		if err != nil {
			http.Error(writer, "no state", http.StatusBadRequest)
			return
		}
		stateRedirectURI, err := mauth.ValidateRedirectionString(state.RedirectURI)
		if err != nil {
			http.Error(writer, "no state", http.StatusBadRequest)
			return
		}
		if qError := request.URL.Query().Get("error"); qError != "" {
			urlWithQuery(stateRedirectURI, "error", qError)
			http.Redirect(writer, request, stateRedirectURI.String(), http.StatusTemporaryRedirect)
			return
		}

		code := request.URL.Query().Get("code")

		timeout, cancelTimeout := context.WithTimeout(request.Context(), time.Second*5)
		defer cancelTimeout()

		request = request.WithContext(timeout)

		emails, err := authenticator.ReadEmails(request.Context(), state, code)
		if err != nil {
			urlWithQuery(stateRedirectURI, "error", "failed")
			http.Redirect(writer, request, stateRedirectURI.String(), http.StatusTemporaryRedirect)
			return
		}
		tkn := paseto.NewToken()
		tkn.SetString("emails", strings.Join(emails, ","))
		tkn.SetExpiration(time.Now().Add(time.Minute * 10))
		tknString := tkn.V4Encrypt(secret, nil)
		urlWithQuery(stateRedirectURI, "code", tknString)
		http.Redirect(writer, request, stateRedirectURI.String(), http.StatusTemporaryRedirect)
	})

	fak.Throw(http.ListenAndServe(listenAddr, mux))
}
