// Fake Daum/Netmarble auth HTTP server.
//
// Goley.exe (launcher) talks to:
//   http://member.daum.netmarble.net/member/ActGameAuth.asp
//   http://member.daum.netmarble.net/member/RefGameAuth.asp
//   http://www.netmarble.com/ssoact.asp
//   http://www.netmarble.com/ssocookie.asp
//
// We need to:
//   1) Match these URLs (after hosts redirect to 127.0.0.1)
//   2) Return a session cookie / SSO token that the launcher accepts
//   3) Hand off to the Entry game server (TCP, port 2270)
//
// Listens on port 80 by default (admin required on Windows for <1024).
// On the dev host, port 80 is already used by the patch server; this auth
// stub listens on port 8081 unless DAUM_ADDR overrides it.
//
// For production this would live behind the same vhost as the patch server;
// for now they are separate processes.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const defaultAddr = ":8081"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	addr := defaultAddr
	if v := os.Getenv("DAUM_ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()

	// ActGameAuth.asp -- primary login endpoint
	mux.HandleFunc("/member/ActGameAuth.asp", func(w http.ResponseWriter, r *http.Request) {
		logRequest(log, "ActGameAuth", r)
		// Original responds with an INI-style payload containing a session
		// cookie / token. Format unknown; this is a placeholder.
		setSessionCookie(w)
		fmt.Fprintf(w, "result=0\nuserid=goley_test\ntoken=fake_token_%d\nserver_ip=127.0.0.1\nserver_port=2270\n",
			time.Now().Unix())
	})

	// RefGameAuth.asp -- refresh existing session
	mux.HandleFunc("/member/RefGameAuth.asp", func(w http.ResponseWriter, r *http.Request) {
		logRequest(log, "RefGameAuth", r)
		setSessionCookie(w)
		fmt.Fprintf(w, "result=0\ntoken=fake_token_refreshed_%d\n", time.Now().Unix())
	})

	// ssoact.asp -- SSO activation
	mux.HandleFunc("/ssoact.asp", func(w http.ResponseWriter, r *http.Request) {
		logRequest(log, "ssoact", r)
		setSessionCookie(w)
		fmt.Fprintf(w, "result=0")
	})

	// ssocookie.asp -- set SSO cookie
	mux.HandleFunc("/ssocookie.asp", func(w http.ResponseWriter, r *http.Request) {
		logRequest(log, "ssocookie", r)
		setSessionCookie(w)
		fmt.Fprintf(w, "OK")
	})

	// Catch-all so we see what other endpoints the client tries
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logRequest(log, "catchall", r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "")
	})

	log.Info("daum auth stub starting", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

func setSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    "NMSESSION",
		Value:   fmt.Sprintf("fake_session_%d", time.Now().Unix()),
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})
}

func logRequest(log *slog.Logger, label string, r *http.Request) {
	log.Info("http req",
		"label", label,
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"ua", r.UserAgent(),
	)
}
