package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type Queue interface {
	Enqueue(context.Context, string, string) error
}
type Redis struct{ client *redis.Client }

func (r *Redis) Enqueue(ctx context.Context, tenant, run string) error {
	return r.client.XAdd(ctx, &redis.XAddArgs{Stream: "agent-runs", Values: map[string]any{"tenant": tenant, "run": run}}).Err()
}

var rateScript = redis.NewScript(`local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],120) end; return n`)

func (r *Redis) Allow(ctx context.Context, key string, max int) (bool, error) {
	key = "rate:" + key + ":" + strconv.FormatInt(time.Now().Unix()/60, 10)
	n, e := rateScript.Run(ctx, r.client, []string{key}).Int()
	return n <= max, e
}
func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
func telemetry(ctx context.Context) func(context.Context) error {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return func(context.Context) error { return nil }
	}
	exporter, e := otlptracehttp.New(ctx)
	if e != nil {
		log.Fatal(e)
	}
	p := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", "secureagent-gateway"))))
	otel.SetTracerProvider(p)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return p.Shutdown
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdown := telemetry(ctx)
	cfg := Config{JWTSecret: os.Getenv("JWT_SECRET"), WorkerSecret: os.Getenv("WORKER_SECRET"), MaxTools: envInt(os.Getenv("MAX_TOOL_CALLS"), 25), MaxTokens: envInt(os.Getenv("MAX_TOKENS"), 20000), Timeout: envInt(os.Getenv("RUN_TIMEOUT_SECONDS"), 300), Rate: envInt(os.Getenv("RATE_LIMIT_PER_MINUTE"), 120), MaxCost: 0.5}
	inputPrice, e := strconv.ParseFloat(env("MODEL_INPUT_USD_PER_MILLION", "10"), 64)
	if e != nil || inputPrice <= 0 {
		log.Fatal("invalid model input reservation price")
	}
	outputPrice, e := strconv.ParseFloat(env("MODEL_OUTPUT_USD_PER_MILLION", "40"), 64)
	if e != nil || outputPrice <= 0 {
		log.Fatal("invalid model output reservation price")
	}
	cfg.ReservationCost = (17000*inputPrice + 1200*outputPrice) / 1000000
	if len(cfg.JWTSecret) < 32 || len(cfg.WorkerSecret) < 32 || cfg.JWTSecret == cfg.WorkerSecret || cfg.JWTSecret == "replace-with-at-least-32-random-characters" || cfg.WorkerSecret == "replace-with-another-32-random-characters" {
		log.Fatal("generate distinct JWT_SECRET and WORKER_SECRET of at least 32 characters")
	}
	if v := os.Getenv("MAX_COST_USD"); v != "" {
		n, e := strconv.ParseFloat(v, 64)
		if e != nil || n <= 0 {
			log.Fatal("invalid MAX_COST_USD")
		}
		cfg.MaxCost = n
	}
	var store Store
	var limiter Limiter
	var queue Queue
	if os.Getenv("DEMO_MEMORY") == "1" {
		store = NewMemory()
		limiter = &localLimiter{counts: map[string]int{}}
		log.Print("ephemeral memory mode: persistence and Redis verification are disabled")
	} else {
		p, e := NewPostgres(ctx, os.Getenv("DATABASE_URL"))
		if e != nil {
			log.Fatal(e)
		}
		defer p.pool.Close()
		store = p
		opts, e := redis.ParseURL(env("REDIS_URL", "redis://redis:6379/0"))
		if e != nil {
			log.Fatal(e)
		}
		client := redis.NewClient(opts)
		defer client.Close()
		if e = client.Ping(ctx).Err(); e != nil {
			log.Fatal(e)
		}
		r := &Redis{client}
		limiter = r
		queue = r
	}
	if e := seed(store, env("DEMO_PASSWORD", "secureagent-demo")); e != nil {
		log.Fatal(e)
	}
	server := &Server{store: store, limiter: limiter, config: cfg, now: time.Now}
	if queue != nil {
		go server.dispatch(ctx, queue)
	}
	h := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(c)
		_ = shutdown(c)
	}()
	log.Printf("gateway listening on %s", h.Addr)
	if e := h.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
		log.Fatal(e)
	}
}
