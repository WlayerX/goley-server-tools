// launcher-web mimics multiple Goley auth/patch endpoints in a single binary.
//
// Hosts file redirects (these must point to 127.0.0.1):
//
//   www.joygame.com / joygame.com           → launcher HTML + patch endpoints
//   cdn.joygamedl.com                       → PatchInfo.bin / Goley.exe / LauncherRestarter.exe
//   member.daum.netmarble.net               → Daum auth (ActGameAuth.asp)
//   www.netmarble.com / netmarble.com       → SSO endpoints (ssoact.asp / ssocookie.asp)
//   cj.netmarble.net / launch.netmarble.net → CJ internal endpoints
//
// The launcher will call into all of these during its boot sequence; we
// answer with the minimum that lets it proceed to Goley_.exe.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uintptr/goley-server/internal/common"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address (use :443 with -cert/-key for HTTPS)")
	webRoot := flag.String("root", "web/launcher", "static files root")
	certFile := flag.String("cert", "", "path to TLS cert PEM (enables HTTPS)")
	keyFile := flag.String("key", "", "path to TLS key PEM")
	flag.Parse()

	log := common.NewLogger("launcher-web")
	defer log.Close()
	log.Logf("=== Goley launcher-web ===")

	abs, _ := filepath.Abs(*webRoot)
	log.Logf("addr=%s root=%s", *addr, abs)

	if _, err := os.Stat(abs); err != nil {
		log.Logf("WARN: webRoot not found: %v (will return 404 for static)", err)
	}

	mux := http.NewServeMux()

	// ---------------------------------------------------------------
	// Netmarble / Daum auth endpoints
	// ---------------------------------------------------------------
	// ActGameAuth.asp -- primary login endpoint. Returns INI-style key=value
	// payload with a session token. Format observed from launcher dumps.
	mux.HandleFunc("/member/ActGameAuth.asp", func(w http.ResponseWriter, r *http.Request) {
		log.Logf("DAUM ActGameAuth %s  q=%s", r.URL.Path, r.URL.RawQuery)
		setSessionCookie(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w,
			"result=0\r\n"+
				"userid=goley_test\r\n"+
				"userserial=1\r\n"+
				"token=fake_token_%d\r\n"+
				"server_ip=127.0.0.1\r\n"+
				"server_port=2270\r\n",
			time.Now().Unix())
		log.Logf("    <<< 200 OK (with token)")
	})

	// RefGameAuth.asp -- refresh existing session
	mux.HandleFunc("/member/RefGameAuth.asp", func(w http.ResponseWriter, r *http.Request) {
		log.Logf("DAUM RefGameAuth %s  q=%s", r.URL.Path, r.URL.RawQuery)
		setSessionCookie(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "result=0\r\ntoken=fake_token_refreshed_%d\r\n", time.Now().Unix())
		log.Logf("    <<< 200 OK")
	})

	// ssoact.asp -- SSO activation (used by both www.netmarble.com and other hosts)
	mux.HandleFunc("/ssoact.asp", func(w http.ResponseWriter, r *http.Request) {
		log.Logf("SSO ssoact %s  q=%s", r.URL.Path, r.URL.RawQuery)
		setSessionCookie(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "result=0")
		log.Logf("    <<< 200 OK")
	})

	// ssocookie.asp -- set SSO cookie
	mux.HandleFunc("/ssocookie.asp", func(w http.ResponseWriter, r *http.Request) {
		log.Logf("SSO ssocookie %s  q=%s", r.URL.Path, r.URL.RawQuery)
		setSessionCookie(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "OK")
		log.Logf("    <<< 200 OK")
	})

	// ---------------------------------------------------------------
	// Default static handler for joygame.com paths
	// ---------------------------------------------------------------
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Logf("%s %s  Host=%s UA=%s", r.Method, r.URL.Path, r.Host, r.UserAgent())

		// Route /launchers/cj/goley/ paths to webRoot
		path := r.URL.Path
		path = strings.TrimPrefix(path, "/launchers/cj/goley/")
		path = strings.TrimPrefix(path, "/launchers/cj/goley")
		if path == "" || path == "/" {
			path = "index.html"
		}

		full := filepath.Join(abs, path)
		data, err := os.ReadFile(full)
		if err != nil {
			http.NotFound(w, r)
			log.Logf("    <<< 404 %s", full)
			return
		}

		w.Header().Set("Content-Type", contentType(full))
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
		log.Logf("    <<< 200 %s (%d bytes)", full, len(data))
	})

	srv := &http.Server{Addr: *addr, Handler: mux}
	if *certFile != "" && *keyFile != "" {
		log.Logf("Listening on %s (HTTPS, cert=%s)", *addr, *certFile)
		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
			log.Logf("FATAL: %v", err)
			os.Exit(1)
		}
	} else {
		log.Logf("Listening on %s (HTTP)", *addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Logf("FATAL: %v", err)
			os.Exit(1)
		}
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

func contentType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".ico":
		return "image/x-icon"
	case ".svg":
		return "image/svg+xml"
	case ".exe":
		return "application/octet-stream"
	}
	return "application/octet-stream"
}

