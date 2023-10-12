SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

CC := gcc
CFLAGS :=
LDFLAGS := -fPIC -shared
INSTALL := install
DESTDIR := /
PREFIX := /usr

GOLDFLAGS := '-extldflags "-static"'

all: script plugin

plugin: defer_simple.c openvpn-plugin.h
	$(CC) $(CFLAGS) $(LDFLAGS) -I. -c defer_simple.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,defer_simple.so -o defer_simple.so defer_simple.o

script: cmd/okta-openvpn/main.go
	CGO_ENABLED=0 go build -o okta_openvpn -a -ldflags $(GOLDFLAGS) cmd/okta-openvpn/main.go

test:
	go test ./pkg/... -v -cover -coverprofile=cover.out -covermode=atomic -coverpkg=./pkg/...

coverage.html: cover.out
	go tool cover -html=cover.out -o coverage.html

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	mkdir -p $(DESTDIR)/etc/openvpn/
	$(INSTALL) -m755 defer_simple.so $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 okta_openvpn $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m644 okta_pinset.cfg $(DESTDIR)/etc/openvpn/okta_pinset.cfg
	$(INSTALL) -m640 okta_openvpn.ini.inc $(DESTDIR)/etc/openvpn/okta_openvpn.ini

clean:
	rm -f *.o
	rm -f *.so
	rm -f okta_openvpn

.PHONY: clean plugin install test
