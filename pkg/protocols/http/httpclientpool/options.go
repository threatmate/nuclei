package httpclientpool

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/rawhttp"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// WithCustomTimeout is a configuration for custom timeout
type WithCustomTimeout struct {
	Timeout time.Duration
}

// RawHttpRequestOpts is a configuration for raw http request
type RawHttpRequestOpts struct {
	// Method is the http method to use
	Method string
	// URL is the url to request
	URL string
	// Path is request path to use
	Path string
	// Headers is the headers to use
	Headers map[string][]string
	// Body is the body to use
	Body io.Reader
	// Options is more client related options
	Options *rawhttp.Options
}

// SendRawRequest sends a raw http request with the provided options and returns http response,
// along with the URL of the hop that answered when a redirect was followed ("" when it was not).
//
// rawhttp follows redirects inside DoRawWithOptions and never says where it landed: the response
// it hands back carries no Request, so a caller reporting where a template matched could only name
// the URL it asked for -- the target -- even when the answer came from wherever the target
// redirected to. So the redirects are followed here instead, one hop at a time, and the last hop
// is returned. The loop is rawhttp v0.1.92's own (client.go, Client.do) so that only the
// reporting changes: the same status test, the same Location handling, the same hop bound, and
// the same request on every hop -- rawhttp re-sends the template's path and raw bytes to each new
// host rather than the Location's path, and so does this.
func SendRawRequest(client *rawhttp.Client, opts *RawHttpRequestOpts) (*http.Response, string, error) {
	followRedirects := opts.Options.FollowRedirects
	hopOptions := *opts.Options
	hopOptions.FollowRedirects = false

	hopURL := opts.URL
	landedURL := ""
	resp, err := client.DoRawWithOptions(opts.Method, hopURL, opts.Path, opts.Headers, opts.Body, &hopOptions)
	for current := 0; err == nil && followRedirects && isRawRedirect(resp.StatusCode) && current <= client.Options.MaxRedirects; current++ {
		_, err = io.Copy(io.Discard, resp.Body)
		if closeErr := resp.Body.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			resp = nil
			break
		}
		hopURL = rawRedirectLocation(hopURL, resp.Header)
		landedURL = hopURL
		resp, err = client.DoRawWithOptions(opts.Method, hopURL, opts.Path, opts.Headers, opts.Body, &hopOptions)
	}
	if err != nil {
		cause := err.Error()
		if stringsutil.ContainsAll(cause, "ReadStatusLine: ", "read: connection reset by peer") {
			// this error is caused when rawhttp client sends a corrupted or malformed request packet to server
			// some servers may attempt gracefully shutdown but most will just abruptly close the connection which results
			// in a connection reset by peer error and this can be safely assumed as 400 Bad Request in terms of normal http flow
			//
			// The reset came from the hop that was being asked, which is opts.URL unless a
			// redirect was followed, so that is the URL the stand-in response is for.
			req, reqErr := http.NewRequest(opts.Method, hopURL, opts.Body)
			if reqErr != nil {
				// failed to build new request mostly because of invalid url or body
				// try again or else return urlErr
				parsed, urlErr := urlutil.ParseAbsoluteURL(hopURL, true)
				if urlErr != nil {
					return nil, landedURL, err
				}
				req, reqErr = http.NewRequest(opts.Method, parsed.Host, opts.Body)
				if reqErr != nil {
					return nil, landedURL, err
				}
				req.URL = parsed.URL
				req.Header = opts.Headers
			}

			// if req is still nil, return error
			if req == nil {
				return nil, landedURL, err
			}

			req.Header = opts.Headers
			resp = &http.Response{
				Request:    req,
				StatusCode: http.StatusBadRequest,
				Status:     http.StatusText(http.StatusBadRequest),
				Body:       io.NopCloser(strings.NewReader("")),
			}
			return resp, landedURL, nil
		}
	}
	return resp, landedURL, err
}

// isRawRedirect is rawhttp's client.Status.IsRedirect: any 3xx except 304, which refers to a
// local resource and is not followed.
func isRawRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400 && statusCode != http.StatusNotModified
}

// rawRedirectLocation is the URL rawhttp's Client.do asks next after a redirect from hopURL. It
// reads the Location key exactly as rawhttp does, and resolves only a value beginning with "/"
// against the hop; any other value, relative or empty, is asked as it stands, and rawhttp fails
// it the same way it always did.
func rawRedirectLocation(hopURL string, header http.Header) string {
	location := strings.Join(header["Location"], " ")
	if !strings.HasPrefix(location, "/") {
		return location
	}
	protocol := "http"
	if strings.HasPrefix(strings.ToLower(hopURL), "https://") {
		protocol = "https"
	}
	// hopURL has already been asked, so it parses: rawhttp fails a URL it cannot parse before
	// any redirect is read.
	host := ""
	if parsed, err := urlutil.ParseURL(hopURL, true); err == nil {
		host = parsed.Host
	}
	if !strings.Contains(host, ":") {
		if protocol == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return fmt.Sprintf("%s://%s%s", protocol, host, location)
}
