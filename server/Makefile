.PHONY: build run-patch run-launcher run-login clean

build:
	go build -o bin/patch-server.exe ./cmd/patch-server
	go build -o bin/launcher-web.exe ./cmd/launcher-web
	go build -o bin/login-server.exe ./cmd/login-server

run-patch: build
	./bin/patch-server.exe

run-launcher: build
	./bin/launcher-web.exe

run-login: build
	./bin/login-server.exe

clean:
	rm -rf bin/
