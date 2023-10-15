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
PLUGIN_PREFIX := /usr/lib/openvpn/plugins
BUILDDIR := build

GOLDFLAGS := -ldflags '-extldflags "-static"'
GOFLAGS := -buildmode=pie -a $(GOLDFLAGS)

all: script plugin libs

$(BUILDDIR):
	mkdir $(BUILDDIR)

plugin: $(BUILDDIR) defer_simple.c openvpn-plugin.h
	$(CC) $(CFLAGS) $(LDFLAGS) -I. -c defer_simple.c -o $(BUILDDIR)/defer_simple.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,defer_simple.so -o $(BUILDDIR)/defer_simple.so $(BUILDDIR)/defer_simple.o

script: $(BUILDDIR) cmd/okta-openvpn/main.go
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BUILDDIR)/okta_openvpn cmd/okta-openvpn/main.go

libs: $(BUILDDIR) defer_okta_openvpn.c openvpn-plugin.h lib/libokta-openvpn.go
	go build -buildmode=c-shared -o $(BUILDDIR)/libokta-openvpn.so lib/libokta-openvpn.go
	$(CC) $(CFLAGS) $(LDFLAGS) -I. -c defer_okta_openvpn.c -o $(BUILDDIR)/defer_okta_openvpn.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,defer_okta_openvpn.so -o $(BUILDDIR)/defer_okta_openvpn.so $(BUILDDIR)/defer_okta_openvpn.o

test:
	# Ensure tests wont fail because of crappy permissions
	chmod -R g-w,o-w testing/fixtures
	go test ./pkg/... -v -cover -coverprofile=cover.out -covermode=atomic -coverpkg=./pkg/...

coverage.html: cover.out
	go tool cover -html=cover.out -o coverage.html

badge: test
	if [ ! -f /tmp/gobadge ]; then \
		curl -sf https://gobinaries.com/github.com/AlexBeauchemin/gobadge@v0.3.0 | PREFIX=/tmp sh; \
	fi
	go tool cover -func=cover.out -o=cover-badge.out
	/tmp/gobadge -filename=cover-badge.out

lint:
	golangci-lint run
	cppcheck --enable=all *.c

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	mkdir -p $(DESTDIR)/etc/openvpn/
	$(INSTALL) -m644 $(BUILDDIR)/defer_simple.so $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m755 $(BUILDDIR)/okta_openvpn $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m644 $(BUILDDIR)/libokta-openvpn.so $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m644 $(BUILDDIR)/defer_okta_openvpn.so $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m644 okta_pinset.cfg $(DESTDIR)/etc/openvpn/okta_pinset.cfg
	$(INSTALL) -m640 okta_openvpn.ini.inc $(DESTDIR)/etc/openvpn/okta_openvpn.ini

clean:
	rm -Rf $(BUILDDIR)
	rm -f cover.out coverage.html cover-badge.out
	rm -f testing/fixtures/validator/valid_control_file
	rm -f testing/fixtures/validator/invalid_control_file
	rm -f testing/fixtures/validator/control_file

.PHONY: clean plugin install test badge lint libs
