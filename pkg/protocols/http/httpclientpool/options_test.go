package httpclientpool

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/rawhttp"
	"github.com/stretchr/testify/require"
)

// rawExchange is what one raw request came to: the answer, and how many requests every server
// involved was asked between them.
type rawExchange struct {
	status   int
	body     string
	requests int64
}

// TestSendRawRequestFollowsRedirectsAsRawhttpDoes holds SendRawRequest's redirect loop to the one
// in rawhttp it replaces: for each chain, the answer and the number of requests it took must be
// what rawhttp's own following produces, and SendRawRequest must also say which hop answered.
func TestSendRawRequestFollowsRedirectsAsRawhttpDoes(t *testing.T) {
	var requests atomic.Int64
	count := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			next(w, r)
		}
	}

	landing := httptest.NewServer(count(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "landed at %s", r.URL.Path)
	}))
	t.Cleanup(landing.Close)

	offHost := httptest.NewServer(count(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", landing.URL+"/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(offHost.Close)

	// rawhttp re-sends the original path on every hop, so a server that redirects "/" to
	// "/next" is asked for "/" again; answer the second request so the chain ends.
	var relativeAsked atomic.Int64
	relative := httptest.NewServer(count(func(w http.ResponseWriter, r *http.Request) {
		if relativeAsked.Add(1)%2 == 1 {
			w.Header().Set("Location", "/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = fmt.Fprintf(w, "second answer at %s", r.URL.Path)
	}))
	t.Cleanup(relative.Close)

	var endless *httptest.Server
	endless = httptest.NewServer(count(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", endless.URL+"/again")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(endless.Close)

	// Written by hand: net/http sends a 304 with no Content-Length, and rawhttp then waits for a
	// body until its timeout, which is rawhttp's own behaviour and beside the point here.
	notModified := httptest.NewServer(count(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 304 Not Modified\r\nLocation: %s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", landing.URL)
		_ = buf.Flush()
	}))
	t.Cleanup(notModified.Close)

	const maxRedirects = 2
	clientOptions := *rawhttp.DefaultOptions
	clientOptions.MaxRedirects = maxRedirects
	client := rawhttp.NewClient(&clientOptions)
	t.Cleanup(client.Close)

	read := func(t *testing.T, resp *http.Response, err error) rawExchange {
		t.Helper()
		require.NoError(t, err)
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		require.NoError(t, resp.Body.Close())
		return rawExchange{status: resp.StatusCode, body: string(body), requests: requests.Swap(0)}
	}

	for _, tc := range []struct {
		name     string
		url      string
		follow   bool
		wantLand string
	}{
		{name: "off-host absolute redirect", url: offHost.URL, follow: true, wantLand: landing.URL + "/elsewhere"},
		{name: "redirect relative to the hop", url: relative.URL, follow: true, wantLand: relative.URL + "/next"},
		{name: "hop bound reached", url: endless.URL, follow: true, wantLand: endless.URL + "/again"},
		{name: "304 is not a redirect", url: notModified.URL, follow: true},
		{name: "redirects not asked for", url: offHost.URL, follow: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := clientOptions
			options.FollowRedirects = tc.follow

			requests.Store(0)
			relativeAsked.Store(0)
			resp, err := client.DoRawWithOptions(http.MethodGet, tc.url, "/", nil, nil, &options)
			want := read(t, resp, err)

			relativeAsked.Store(0)
			resp, landed, err := SendRawRequest(client, &RawHttpRequestOpts{
				Method:  http.MethodGet,
				URL:     tc.url,
				Path:    "/",
				Options: &options,
			})
			got := read(t, resp, err)

			require.Equal(t, want, got, "SendRawRequest must answer exactly as rawhttp's own following does")
			require.Equal(t, tc.wantLand, landed, "SendRawRequest must name the hop that answered")
			require.True(t, options.FollowRedirects == tc.follow, "SendRawRequest must not change the caller's options")
		})
	}
}

// TestSendRawRequestNamesTheHopThatReset covers the stand-in 400 for a reset connection when the
// reset came from a hop a redirect led to: it must name that hop, not the URL first asked.
func TestSendRawRequestNamesTheHopThatReset(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Read the request's headers, then reset rather than answer.
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
		}
	}()
	resetURL := "http://" + listener.Addr().String()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", resetURL+"/x")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	clientOptions := *rawhttp.DefaultOptions
	client := rawhttp.NewClient(&clientOptions)
	t.Cleanup(client.Close)
	options := clientOptions
	options.FollowRedirects = true

	resp, landed, err := SendRawRequest(client, &RawHttpRequestOpts{Method: http.MethodGet, URL: redirector.URL, Path: "/", Options: &options})
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "a reset is answered with the stand-in 400")
	require.Equal(t, resetURL+"/x", landed)
	require.Equal(t, listener.Addr().String(), resp.Request.URL.Host, "the stand-in response must name the hop that reset")
}
