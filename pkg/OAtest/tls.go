// SPDX-FileCopyrightText: 2025-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2025-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package OAtest

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	// validPinset has been computed using:
	/*
		cat testing/fixtures/server.crt |\
			openssl x509 -noout -pubkey |\
			openssl rsa	-pubin -outform der 2>/dev/null |\
			openssl dgst -sha256 -binary | base64
	*/
	TLSHost          string = "127.0.0.1"
	TLSPort          string = "2444"
	TLSValidPinset   string = "j69yToSVkR6G7RKEc0qvsA6MysH+luI3wBIihDA20nI="
	TLSInvalidPinset string = "ABCDEF"
)

func StartTestHttpsServer(t *testing.T) *http.Server {
	t.Helper()
	mux := http.NewServeMux()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	srv := http.Server{
		Addr:         fmt.Sprintf("%s:%s", TLSHost, TLSPort),
		Handler:      mux,
		TLSConfig:    cfg,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
	go func() {
		// set SO_REUSEPORT on the underlying socket to prevent address already in use error
		lc := net.ListenConfig{
			Control: func(network, address string, conn syscall.RawConn) error {
				var operr error
				if err := conn.Control(func(fd uintptr) {
					operr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}); err != nil {
					return err
				}
				return operr
			},
		}

		ln, err := lc.Listen(context.Background(), "tcp", srv.Addr)
		require.NoError(t, err, "Fail to have test Http server listen")
		if err := srv.ServeTLS(ln, "../../testing/fixtures/utils/server.crt",
			"../../testing/fixtures/utils/server.key"); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()
	t.Cleanup(func() { srv.Close() })
	return &srv
}
