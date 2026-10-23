// Copyright 2026 ScopeDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Callback struct {
	Code             string
	State            string
	Issuer           string
	Error            string
	ErrorDescription string
}

// Loopback is a one-shot HTTP listener on a loopback address that receives the authorization
// redirect. It binds 127.0.0.1 so the redirect never depends on name resolution (RFC 8252 §8.3).
type Loopback struct {
	listener net.Listener
	server   *http.Server
	results  chan Callback
	serveErr chan error
	once     sync.Once
}

const callbackPath = "/callback"

func NewLoopback() (*Loopback, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for the authorization redirect: %w", err)
	}
	loopback := &Loopback{
		listener: listener,
		results:  make(chan Callback, 1),
		serveErr: make(chan error, 1),
	}
	loopback.server = &http.Server{
		Handler:           http.HandlerFunc(loopback.handle),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		err := loopback.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		loopback.serveErr <- err
	}()
	return loopback, nil
}

// RedirectURI is the exact redirect_uri the authorization request must carry.
func (l *Loopback) RedirectURI() string {
	return "http://" + l.listener.Addr().String() + callbackPath
}

func (l *Loopback) Wait(ctx context.Context) (Callback, error) {
	select {
	case <-ctx.Done():
		return Callback{}, ctx.Err()
	case err := <-l.serveErr:
		if err == nil {
			return Callback{}, errors.New("the authorization redirect listener stopped")
		}
		return Callback{}, err
	case callback := <-l.results:
		return callback, nil
	}
}

func (l *Loopback) Close() error {
	var err error
	l.once.Do(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = l.server.Shutdown(shutdownCtx)
	})
	return err
}

func (l *Loopback) handle(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != callbackPath {
		http.NotFound(writer, request)
		return
	}
	query := request.URL.Query()
	callback := Callback{
		Code:             query.Get("code"),
		State:            query.Get("state"),
		Issuer:           query.Get("iss"),
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	if callback.Error != "" {
		_, _ = writer.Write([]byte(callbackErrorPage))
	} else {
		_, _ = writer.Write([]byte(callbackSuccessPage))
	}
	select {
	case l.results <- callback:
	default:
	}
}

const callbackSuccessPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<title>Scope CLI</title></head><body><p>You can close this window and return to your terminal.</p></body></html>`

const callbackErrorPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<title>Scope CLI</title></head><body><p>This login was not completed. Return to your terminal for details.</p></body></html>`
