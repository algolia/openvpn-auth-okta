SHELL := bash
USERNAME := $(shell echo $$USER)
OS_FAMILY := $(shell . /etc/os-release && echo $$ID_LIKE)
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

GOVENDOR_FLAG :=
ifeq ($(USERNAME), abuild)
GOVENDOR_FLAG := -mod=vendor
endif
GOLDFLAGS := '-extldflags "-static"'

all: script plugin

plugin: defer_simple.c openvpn-plugin.h
	$(CC) $(CFLAGS) $(LDFLAGS) -I. -c defer_simple.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,defer_simple.so -o defer_simple.so defer_simple.o

script: cmd/okta-openvpn/main.go
ifeq ($(USERNAME), abuild)
ifeq ($(OS_FAMILY), debian)
	tar xf ../SOURCES/vendor.tar.gz
else
	tar xf ../../SOURCES/vendor.tar.gz
endif
endif
	CGO_ENABLED=0 go build $(GOVENDOR_FLAG) -o okta_openvpn -a -ldflags $(GOLDFLAGS) cmd/okta-openvpn/main.go

ifneq ($(USERNAME), abuild)
test:
	# Ensure tests wont fail because of crappy permissions during OBS build
	chmod -R g-w,o-w testing/fixtures
	go test ./pkg/... -v -cover -coverprofile=cover.out -covermode=atomic -coverpkg=./pkg/...

coverage.html: cover.out
	go tool cover -html=cover.out -o coverage.html
endif

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
