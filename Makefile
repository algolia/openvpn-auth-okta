SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
UNAME_S := $(shell uname -s)

INSTALL := install
CC := gcc
INC := -I. -I./build
CFLAGS := -fPIC $(INC) -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS := -shared -fPIC

DESTDIR :=
LIB_PREFIX := /usr/lib
PLUGIN_DIR := openvpn/plugins
BUILDDIR := build

GOPLUGIN_LDFLAGS := -ldflags '-s -w -extldflags "-static"'
GOPLUGIN_FLAGS := -trimpath -buildmode=pie -a $(GOPLUGIN_LDFLAGS)

ifeq ($(UNAME_S),Linux)
LIBOKTA_LDFLAGS := -ldflags '-s -w -extldflags -Wl,-soname,libokta-auth-validator.so'
CPLUGIN_LDFLAGS := $(LDFLAGS) -Wl,-soname,openvpn-plugin-auth-okta.so
else
# MacOs X
LIBOKTA_LDFLAGS := -ldflags '-s -w -extldflags -Wl,-install_name,libokta-auth-validator.so'
CPLUGIN_LDFLAGS := $(LDFLAGS) -Wl,-install_name,openvpn-plugin-auth-okta.so
endif
LIBOKTA_FLAGS := -trimpath -buildmode=c-shared $(LIBOKTA_LDFLAGS)

PKG_SRC := $(shell ls pkg/*/*.go | grep -v "_test.go")
PLUGIN_DEPS := $(BUILDDIR)/libokta-auth-validator.so $(BUILDDIR)/openvpn-plugin-auth-okta.o openvpn-plugin.h


all: binary plugin

$(BUILDDIR):
	mkdir $(BUILDDIR)

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build the plugin as a standalone binary
binary: $(BUILDDIR)/okta-auth-validator
$(BUILDDIR)/okta-auth-validator: cmd/okta-auth-validator/main.go $(PKG_SRC) | $(BUILDDIR)
	CGO_ENABLED=0 go build $(GOPLUGIN_FLAGS) -o $(BUILDDIR)/okta-auth-validator cmd/okta-auth-validator/main.go

# Build the openvpn-plugin-auth-okta plugin (linked against the Go c-shared lib)
$(BUILDDIR)/openvpn-plugin-auth-okta.so: $(PLUGIN_DEPS)
	$(CC) $(CPLUGIN_LDFLAGS) -o $(BUILDDIR)/openvpn-plugin-auth-okta.so $(BUILDDIR)/openvpn-plugin-auth-okta.o

# Build the okta-auth-validator shared lib (Golang c-shared)
$(BUILDDIR)/libokta-auth-validator.so: lib/libokta-auth-validator.go $(PKG_SRC) | $(BUILDDIR)
	go build $(LIBOKTA_FLAGS) -o $(BUILDDIR)/libokta-auth-validator.so lib/libokta-auth-validator.go

# Build all shared libraries
plugin: $(BUILDDIR)/libokta-auth-validator.so $(BUILDDIR)/openvpn-plugin-auth-okta.so

test: $(BUILDDIR)/cover.out

coverage: $(BUILDDIR)/coverage.html

# Run gobagde to update the README coverage badge after golang tests
badge: $(BUILDDIR)/cover-badge.out
	if [ ! -f /tmp/gobadge ]; then \
		curl -sf https://gobinaries.com/github.com/AlexBeauchemin/gobadge@v0.3.0 | PREFIX=/tmp sh; \
	fi
	/tmp/gobadge -filename=$(BUILDDIR)/cover-badge.out

# Run tests that generates the cover.out
$(BUILDDIR)/cover.out: | $(BUILDDIR)
	# Ensure tests wont fail because of crappy permissions
	chmod -R g-w,o-w testing/fixtures
	go test ./pkg/... -v -cover -coverprofile=$(BUILDDIR)/cover.out -covermode=atomic -coverpkg=./pkg/...

# Creates the coverage.html
$(BUILDDIR)/coverage.html: $(BUILDDIR)/cover.out
	go tool cover -html=$(BUILDDIR)/cover.out -o $(BUILDDIR)/coverage.html

# Creates the cover-badgeout (needed for README badge link creation)
$(BUILDDIR)/cover-badge.out: $(BUILDDIR)/cover.out
	go tool cover -func=$(BUILDDIR)/cover.out -o=$(BUILDDIR)/cover-badge.out


# You'll need to install golangci-lint and cppcheck
# see https://github.com/danmar/cppcheck#packages
# https://github.com/golangci/golangci-lint#install-golangci-lint
lint:
	golangci-lint run
	cppcheck $(INC) --enable=all --disable=missingInclude --check-level=exhaustive *.c

install: all
	mkdir -p $(DESTDIR)/$(LIB_PREFIX)/$(PLUGIN_DIR)
	mkdir -p $(DESTDIR)/etc/okta-auth-validator/
	mkdir -p $(DESTDIR)/usr/include
	mkdir -p $(DESTDIR)/usr/bin
	$(INSTALL) -m755 $(BUILDDIR)/okta-auth-validator $(DESTDIR)/usr/bin/
	$(INSTALL) -m644 $(BUILDDIR)/libokta-auth-validator.so $(DESTDIR)/$(LIB_PREFIX)/
	$(INSTALL) -m644 $(BUILDDIR)/libokta-auth-validator.h $(DESTDIR)/usr/include/
	$(INSTALL) -m644 $(BUILDDIR)/openvpn-plugin-auth-okta.so $(DESTDIR)/$(LIB_PREFIX)/$(PLUGIN_DIR)/
	if [ ! -f $(DESTDIR)/etc/okta-auth-validator/pinset.cfg ]; then \
		$(INSTALL) -m644 config/pinset.cfg $(DESTDIR)/etc/okta-auth-validator/pinset.cfg; \
	fi
	if [ ! -f $(DESTDIR)/etc/okta-auth-validator/api.ini ]; then \
		$(INSTALL) -m640 config/api.ini.inc $(DESTDIR)/etc/okta-auth-validator/api.ini; \
	fi

clean:
	rm -Rf $(BUILDDIR)
	rm -f testing/fixtures/validator/valid_control_file
	rm -f testing/fixtures/validator/invalid_control_file
	rm -f testing/fixtures/validator/control_file

.PHONY: clean binary install lint badge coverage test plugin
