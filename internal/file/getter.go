package file

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-getter"
	"github.com/hashicorp/go-getter/helper/url"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype-db/internal/log"
)

var (
	archiveExtensions   = getterDecompressorNames()
	ErrNonArchiveSource = fmt.Errorf("non-archive sources are not supported for directory destinations")
)

type Getter interface {
	// GetFile downloads the give URL into the given path. The URL must reference a single file.
	GetFile(dst, src string, monitor ...*progress.Manual) error

	// GetToDir downloads the resource found at the `src` URL into the given `dst` directory.
	// The directory must already exist, and the remote resource MUST BE AN ARCHIVE (e.g. `.tar.gz`).
	GetToDir(dst, src string, monitor ...*progress.Manual) error
}

type hashiGoGetter struct {
	httpGetter getter.HttpGetter
}

// NewGetter creates and returns a new Getter. Providing an http.Client is optional. If one is provided,
// it will be used for all HTTP(S) getting; otherwise, go-getter's default getters will be used.
func NewGetter(httpClient *http.Client) Getter {
	return &hashiGoGetter{
		httpGetter: getter.HttpGetter{
			Client: httpClient,
		},
	}
}

func NewDefaultGetter() Getter {
	return NewGetter(cleanhttp.DefaultClient())
}

func HTTPClientWithCerts(fileSystem fs.FS, caCertPath string) (*http.Client, error) {
	httpClient := cleanhttp.DefaultClient()
	if caCertPath != "" {
		rootCAs := x509.NewCertPool()

		pemBytes, err := fs.ReadFile(fileSystem, caCertPath)
		if err != nil {
			return nil, fmt.Errorf("unable to configure root CAs for curator: %w", err)
		}
		rootCAs.AppendCertsFromPEM(pemBytes)

		httpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		}
	}
	return httpClient, nil
}

func (g hashiGoGetter) GetFile(dst, src string, monitors ...*progress.Manual) error {
	if len(monitors) > 1 {
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}

	return getWithRetry(getterClient(dst, src, false, g.httpGetter, monitors))
}

func (g hashiGoGetter) GetToDir(dst, src string, monitors ...*progress.Manual) error {
	// though there are multiple getters, only the http/https getter requires extra validation
	if err := validateHTTPSource(src); err != nil {
		return err
	}
	if len(monitors) > 1 {
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}

	return getWithRetry(getterClient(dst, src, true, g.httpGetter, monitors))
}

func getWithRetry(client *getter.Client) error {
	var err error
	attempt := 1
	for interval := range retryIntervals() {
		fields := logger.Fields{
			"url": client.Src,
			"to":  client.Dst,
		}

		if attempt > 1 {
			fields["attempt"] = attempt
		}

		log.WithFields(fields).Info("downloading file")

		err = client.Get()
		if err == nil {
			break
		}

		time.Sleep(interval)
		attempt++
	}
	return err
}

func retryIntervals() <-chan time.Duration {
	return exponentialBackoffDurations(250*time.Millisecond, 5*time.Second, 2)
}

func exponentialBackoffDurations(minDuration, maxDuration time.Duration, step float64) <-chan time.Duration {
	sleepDurations := make(chan time.Duration)
	go func() {
		defer close(sleepDurations)
		for attempt := 0; ; attempt++ {
			duration := exponentialBackoffDuration(minDuration, maxDuration, step, attempt)

			sleepDurations <- duration

			if duration == maxDuration {
				break
			}
		}
	}()
	return sleepDurations
}

func exponentialBackoffDuration(minDuration, maxDuration time.Duration, step float64, attempt int) time.Duration {
	duration := time.Duration(float64(minDuration) * math.Pow(step, float64(attempt)))
	if duration < minDuration {
		return minDuration
	} else if duration > maxDuration {
		return maxDuration
	}
	return duration
}

func validateHTTPSource(src string) error {
	// we are ignoring any sources that are not destined to use the http getter object
	if !hasAnyOfPrefixes(src, "http://", "https://") {
		return nil
	}

	u, err := url.Parse(src)
	if err != nil {
		return fmt.Errorf("bad URL provided %q: %w", src, err)
	}
	// only allow for sources with archive extensions
	if !hasAnyOfSuffixes(u.Path, archiveExtensions...) {
		return ErrNonArchiveSource
	}
	return nil
}

func getterClient(dst, src string, dir bool, httpGetter getter.HttpGetter, monitors []*progress.Manual) *getter.Client {
	client := &getter.Client{
		Src: src,
		Dst: dst,
		Dir: dir,
		Getters: map[string]getter.Getter{
			"http":  &httpGetter,
			"https": &httpGetter,
			// note: these are the default getters from https://github.com/hashicorp/go-getter/blob/v1.5.9/get.go#L68-L74
			// it is possible that other implementations need to account for custom httpclient injection, however,
			// that has not been accounted for at this time.
			"file": new(getter.FileGetter),
			"git":  new(getter.GitGetter),
			"gcs":  new(getter.GCSGetter),
			"hg":   new(getter.HgGetter),
			"s3":   new(getter.S3Getter),
		},
		Options: mapToGetterClientOptions(monitors),
	}

	return client
}

func withProgress(monitor *progress.Manual) func(client *getter.Client) error {
	return getter.WithProgress(
		&progressAdapter{monitor: monitor},
	)
}

func mapToGetterClientOptions(monitors []*progress.Manual) []getter.ClientOption {
	// TODO: This function is no longer needed once a generic `map` method is available.

	var result []getter.ClientOption

	for _, monitor := range monitors {
		result = append(result, withProgress(monitor))
	}

	return result
}

type readCloser struct {
	progress.Reader
}

func (c *readCloser) Close() error { return nil }

type progressAdapter struct {
	monitor *progress.Manual
}

func (a *progressAdapter) TrackProgress(_ string, currentSize, totalSize int64, stream io.ReadCloser) io.ReadCloser {
	a.monitor.N = currentSize
	a.monitor.Total = totalSize
	return &readCloser{
		Reader: *progress.NewProxyReader(stream, a.monitor),
	}
}

func getterDecompressorNames() (names []string) {
	for name := range getter.Decompressors {
		names = append(names, name)
	}
	return names
}

// hasAnyOfSuffixes returns an indication if the given string has any of the given suffixes.
func hasAnyOfSuffixes(input string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(input, suffix) {
			return true
		}
	}

	return false
}

// hasAnyOfPrefixes returns an indication if the given string has any of the given prefixes.
func hasAnyOfPrefixes(input string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(input, prefix) {
			return true
		}
	}

	return false
}
