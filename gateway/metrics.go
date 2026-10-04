package main

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type metricValue struct {
	count   int
	seconds float64
	buckets []int
}
type metrics struct {
	mu       sync.Mutex
	requests map[string]*metricValue
}

var bounds = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 5}

type measuredWriter struct {
	http.ResponseWriter
	status int
}

func (w *measuredWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *measuredWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (m *metrics) observe(status int, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%d", status)
	v := m.requests[key]
	if v == nil {
		v = &metricValue{buckets: make([]int, len(bounds))}
		m.requests[key] = v
	}
	v.count++
	v.seconds += d.Seconds()
	for i, bound := range bounds {
		if d.Seconds() <= bound {
			v.buckets[i]++
		}
	}
}
func (m *metrics) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP secureagent_http_duration_seconds Gateway request latency by status.")
	fmt.Fprintln(w, "# TYPE secureagent_http_duration_seconds histogram")
	keys := []string{}
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m.requests[k]
		for i, b := range bounds {
			fmt.Fprintf(w, "secureagent_http_duration_seconds_bucket{status=%q,le=%q} %d\n", k, fmt.Sprint(b), v.buckets[i])
		}
		fmt.Fprintf(w, "secureagent_http_duration_seconds_bucket{status=%q,le=\"+Inf\"} %d\n", k, v.count)
		fmt.Fprintf(w, "secureagent_http_duration_seconds_count{status=%q} %d\nsecureagent_http_duration_seconds_sum{status=%q} %f\n", k, v.count, k, v.seconds)
	}
}
