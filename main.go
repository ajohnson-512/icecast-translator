// You know what they say - when you're tired of stats and metrics, you're tired of life.
// Guess what. I love metrics.
// So welcome to the super-duper 'Brownbox-Exporter' - Thanks for that Jesse.
// No really I call it the Icecast XML Translator.
// The goal here translate Icecast XML stats into OpenMetrics format for ingestion
// into Prometheus.
// Written by Alex, 6/09/23, updated 6/11/23.
// 6/17/23 -- Newest version. updated to include go routines to more efficiently
// scrape multiple targets at the same time.

package main

// Packages required to make this work.
import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const version = "1.0.3" // Update with your desired version number

// We're pulling some stats out of the Icy/Adswizz XML.
type Source struct {
	MountPoint     string `xml:"mount,attr"`
	Listeners      int    `xml:"listeners"`
	TotalBytesSent int64  `xml:"total_bytes_sent"`
	TotalBytesRecv int64  `xml:"total_bytes_read"`
}

// This XML structure.
type IcecastStats struct {
	XMLName xml.Name `xml:"icestats"`
	Sources []Source `xml:"source"`
}

// Some definitions of what we want to display and how.
type CustomCollector struct {
	listenersMetric *prometheus.GaugeVec
	transmitMetric  *prometheus.GaugeVec
	recvMetric      *prometheus.GaugeVec
	client          *http.Client
}

// Displaying our parsed XML data onto the /metrics page.
func NewCustomCollector() *CustomCollector {
	return &CustomCollector{
		listenersMetric: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "icecast_listeners",
			Help: "Number of listeners per mount point",
		}, []string{"mountpoint"}),
		transmitMetric: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mountpoint_transmit",
			Help: "Data transmit per mount point",
		}, []string{"mountpoint"}),
		recvMetric: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mountpoint_recv",
			Help: "Data receive per mount point",
		}, []string{"mountpoint"}),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 8 * time.Second,
		},
	}
}

// Let's describe the metrics.
func (c *CustomCollector) Describe(ch chan<- *prometheus.Desc) {
	c.listenersMetric.Describe(ch)
	c.transmitMetric.Describe(ch)
	c.recvMetric.Describe(ch)
}

func (c *CustomCollector) Collect(ch chan<- prometheus.Metric) {
	c.listenersMetric.Collect(ch)
	c.transmitMetric.Collect(ch)
	c.recvMetric.Collect(ch)
}

// Here's where the magic happens: This parses the requests from Prometheus, determining
// the protocol scheme, cracking open the basic auth credentials and inserting them into
// the URL structure. Then our function displays those stats on a dedicated /metrics page
// for each call.
// Error handling included for those who need it.
func (c *CustomCollector) updateMetrics(r *http.Request, scheme, domain, port, uri, target string) error {
	auth := r.Header.Get("Authorization")
	authParts := strings.SplitN(auth, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		return fmt.Errorf("invalid or missing Authorization header")
	}

	data, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		return fmt.Errorf("error decoding Authorization header: %v", err)
	}

	creds := bytes.SplitN(data, []byte(":"), 2)
	if len(creds) != 2 {
		return fmt.Errorf("invalid Authorization data format, expected 'username:password'")
	}

	username := url.QueryEscape(string(creds[0]))
	password := url.QueryEscape(string(creds[1]))

	url := fmt.Sprintf("%s://%s:%s@%s:%s%s", scheme, username, password, domain, port, uri)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %v", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error retrieving Icecast stats for target %s: %v", target, err)
	}
	defer resp.Body.Close()

	decoder := xml.NewDecoder(resp.Body)

	var stats IcecastStats
	err = decoder.Decode(&stats)
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("error parsing Icecast stats XML for domain %s: %v", domain, err)
		}
		return fmt.Errorf("error parsing Icecast stats XML: %v", err)
	}

	c.listenersMetric.Reset()
	c.transmitMetric.Reset()
	c.recvMetric.Reset()

	for _, source := range stats.Sources {
		mountpoint := source.MountPoint
		c.listenersMetric.WithLabelValues(mountpoint).Set(float64(source.Listeners))
		c.transmitMetric.WithLabelValues(mountpoint).Set(float64(source.TotalBytesSent))
		c.recvMetric.WithLabelValues(mountpoint).Set(float64(source.TotalBytesRecv))
	}

	return nil
}

// Dis the main man.
func main() {

	log.Printf("Starting Icecast XML Translator v%s\n", version)

	log.SetOutput(os.Stdout)
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		domain := queryParams.Get("domain")
		target := queryParams.Get("target")

		if target == "" && domain == "" {
			http.Error(w, "No target/domain specified", http.StatusBadRequest)
			return
		}

		domain = domain + target
		port := queryParams.Get("port")
		uri := queryParams.Get("uri")
		scheme := queryParams.Get("scheme")

		customRegistry := prometheus.NewRegistry()
		customCollector := NewCustomCollector()
		customRegistry.MustRegister(customCollector)

		var wg sync.WaitGroup
		var once sync.Once
		var scrapeError error

		target = fmt.Sprintf("%s;%s;%s", scheme, domain, port)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := customCollector.updateMetrics(r, scheme, domain, port, uri, target); err != nil {
				// Check if the error is related to parsing the URL.
				if urlErr, ok := err.(*url.Error); ok {
					if strings.Contains(urlErr.Error(), "missing protocol scheme") {
						err = fmt.Errorf("error creating HTTP request: missing protocol scheme")
					}
				}
				once.Do(func() {
					scrapeError = err
				})
			}
		}()

		wg.Wait()

		if scrapeError != nil {
			log.Printf("Scrape error: %v\n", scrapeError)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		handler := promhttp.HandlerFor(customRegistry, promhttp.HandlerOpts{})
		handler.ServeHTTP(w, r)
	})

	log.Println("Server started on :8085")
	http.ListenAndServe(":8085", nil)
}
