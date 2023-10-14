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
	CGO_ENABLED=0 go build -buildmode=pie -o okta_openvpn -a -ldflags $(GOLDFLAGS) cmd/okta-openvpn/main.go

# Disable tests on OBS as we have no network (especially for tls.Dial)
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
	go tool cover -func=cover.out -o=cover.out
	/tmp/gobadge -filename=cover.out

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
	rm -f cover.out coverage.html
	rm -f testing/fixtures/validator/valid_control_file
	rm -f testing/fixtures/validator/invalid_control_file
	rm -f testing/fixtures/validator/control_file

.PHONY: clean plugin install test
