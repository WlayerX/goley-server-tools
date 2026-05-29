// patch-server mimics http://cdn.joygamedl.com/chagu/Real_Server_Patch/
//
// Endpoints (all observed from RE):
//   GET /chagu/Real_Server_Patch/PatchInfo.bin?p=<unix_ts>      → empty 200
//   GET /chagu/Real_Server_Patch/HashV2.VLL?p=<unix_ts>         → empty 200
//   GET /chagu/Real_Server_Patch/Goley.exe?p=<unix_ts>          → serves real local Goley.exe (hash match)
//   GET /chagu/Real_Server_Patch/LauncherRestarter.exe?p=<ts>   → 404
//   GET /chagu/Real_Server_Patch/<anyfile>                       → serves from local install if found, else 404
package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/uintptr/goley-server/internal/common"
)

func main() {
	addr := flag.String("addr", ":80", "listen address")
	gameDir := flag.String("game-dir", `C:\Joygame\Goley`, "Goley install directory (source of files to serve)")
	flag.Parse()

	log := common.NewLogger("patch-server")
	defer log.Close()
	log.Logf("=== Goley patch-server ===")
	log.Logf("addr=%s gameDir=%s", *addr, *gameDir)

	if _, err := os.Stat(*gameDir); err != nil {
		log.Logf("WARN: gameDir not accessible: %v", err)
	}

	h := &handler{gameDir: *gameDir, log: log}
	srv := &http.Server{Addr: *addr, Handler: h}
	log.Logf("Listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Logf("FATAL: %v", err)
		os.Exit(1)
	}
}

type handler struct {
	gameDir string
	log     *common.Logger
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("p")
	h.log.Logf("%s %s  | p=%s  Host=%s UA=%s",
		r.Method, r.URL.Path, q, r.Host, r.UserAgent())

	filename := filepath.Base(r.URL.Path)
	fl := strings.ToLower(filename)

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "close")

	switch fl {
	case "patchinfo.bin":
		h.respond(w, 200, "application/octet-stream", nil, "PatchInfo[empty]")
		return
	case "hashv2.vll":
		h.respond(w, 200, "application/octet-stream", nil, "HashV2[empty]")
		return
	case "goley.exe":
		h.serveLocal(w, filename, "Goley.exe")
		return
	case "launcherrestarter.exe":
		h.respond(w, 404, "text/plain", nil, "LauncherRestarter-404")
		return
	}

	// Generic: try to find file in install dir, else 404
	if local := h.findLocal(filename); local != "" {
		h.serveLocalPath(w, local, filename)
		return
	}
	h.respond(w, 404, "text/plain", nil, "default-404")
}

func (h *handler) respond(w http.ResponseWriter, code int, ctype string, body []byte, label string) {
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(code)
	if body != nil {
		_, _ = w.Write(body)
	}
	h.log.Logf("    <<< %d %s (%d bytes)", code, label, len(body))
}

func (h *handler) serveLocal(w http.ResponseWriter, urlFilename, localName string) {
	path := filepath.Join(h.gameDir, localName)
	h.serveLocalPath(w, path, urlFilename)
}

func (h *handler) serveLocalPath(w http.ResponseWriter, path, label string) {
	data, err := os.ReadFile(path)
	if err != nil {
		h.respond(w, 404, "text/plain", nil, "local-not-found:"+path)
		return
	}
	h.respond(w, 200, "application/octet-stream", data, "local:"+label)
}

// findLocal recursively searches gameDir for a file matching filename.
func (h *handler) findLocal(filename string) string {
	var found string
	_ = filepath.WalkDir(h.gameDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() == filename {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
