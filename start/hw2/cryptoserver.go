package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func readJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected extra json")
	}
	return nil
}

type user struct {
	Username     string
	PasswordHash []byte
	CreatedAt    time.Time
}

type userStore struct {
	mu    sync.RWMutex
	users map[string]user
}

func newUserStore() *userStore {
	return &userStore{users: make(map[string]user)}
}

var (
	errUserExists   = errors.New("user exists")
	errUserNotFound = errors.New("user not found")
	errBadPassword  = errors.New("bad password")
)

func (s *userStore) create(username, password string) (user, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return user{}, errors.New("invalid credentials")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[strings.ToLower(username)]; ok {
		return user{}, errUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return user{}, err
	}
	u := user{
		Username:     username,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}
	s.users[strings.ToLower(username)] = u
	return u, nil
}

func (s *userStore) verify(username, password string) (user, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return user{}, errors.New("invalid credentials")
	}
	s.mu.RLock()
	u, ok := s.users[strings.ToLower(username)]
	s.mu.RUnlock()
	if !ok {
		return user{}, errUserNotFound
	}
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
		return user{}, errBadPassword
	}
	return u, nil
}

type jwtManager struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

func newJWTManager() (*jwtManager, error) {
	secret := os.Getenv("JWT_SECRET")
	if strings.TrimSpace(secret) == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		secret = fmt.Sprintf("%x", b)
	}
	return &jwtManager{
		secret: []byte(secret),
		issuer: "cryptoserver",
		ttl:    24 * time.Hour,
	}, nil
}

func (m *jwtManager) issueToken(username string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub": username,
		"iss": m.issuer,
		"iat": now.Unix(),
		"exp": now.Add(m.ttl).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.secret)
}

func (m *jwtManager) parseToken(token string) (string, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return "", err
	}
	if !parsed.Valid {
		return "", errors.New("invalid token")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}
	sub, _ := claims["sub"].(string)
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return "", errors.New("missing subject")
	}
	return sub, nil
}

type historyEntry struct {
	Price     float64   `json:"price"`
	Timestamp time.Time `json:"timestamp"`
}

type crypto struct {
	Symbol       string        `json:"symbol"`
	Name         string        `json:"name"`
	CurrentPrice float64       `json:"current_price"`
	LastUpdated  time.Time     `json:"last_updated"`
	History      []historyEntry `json:"-"`
}

type cryptoDTO struct {
	Symbol       string  `json:"symbol"`
	Name         string  `json:"name"`
	CurrentPrice float64 `json:"current_price"`
	LastUpdated  string  `json:"last_updated"`
}

func toCryptoDTO(c crypto) cryptoDTO {
	return cryptoDTO{
		Symbol:       c.Symbol,
		Name:         c.Name,
		CurrentPrice: c.CurrentPrice,
		LastUpdated:  c.LastUpdated.UTC().Format(time.RFC3339),
	}
}

type cryptoStore struct {
	mu     sync.RWMutex
	cryptos map[string]*crypto
}

func newCryptoStore() *cryptoStore {
	return &cryptoStore{cryptos: make(map[string]*crypto)}
}

var (
	errCryptoExists   = errors.New("crypto exists")
	errCryptoNotFound = errors.New("crypto not found")
)

func normalizeSymbol(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func (s *cryptoStore) add(c crypto) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeSymbol(c.Symbol)
	if key == "" {
		return errors.New("empty symbol")
	}
	if _, ok := s.cryptos[key]; ok {
		return errCryptoExists
	}
	c.Symbol = key
	cc := c
	s.cryptos[key] = &cc
	return nil
}

func (s *cryptoStore) get(symbol string) (crypto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := normalizeSymbol(symbol)
	c, ok := s.cryptos[key]
	if !ok {
		return crypto{}, errCryptoNotFound
	}
	return *c, nil
}

func (s *cryptoStore) list() []crypto {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]crypto, 0, len(s.cryptos))
	for _, c := range s.cryptos {
		out = append(out, *c)
	}
	return out
}

func (s *cryptoStore) update(symbol string, name string, price float64, ts time.Time) (crypto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeSymbol(symbol)
	c, ok := s.cryptos[key]
	if !ok {
		return crypto{}, errCryptoNotFound
	}
	if strings.TrimSpace(name) != "" {
		c.Name = name
	}
	c.CurrentPrice = price
	c.LastUpdated = ts.UTC()
	c.History = append(c.History, historyEntry{Price: price, Timestamp: c.LastUpdated})
	if len(c.History) > 100 {
		c.History = c.History[len(c.History)-100:]
	}
	return *c, nil
}

func (s *cryptoStore) delete(symbol string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeSymbol(symbol)
	if _, ok := s.cryptos[key]; !ok {
		return errCryptoNotFound
	}
	delete(s.cryptos, key)
	return nil
}

type coingeckoClient struct {
	httpClient *http.Client
	baseURL    string

	mu           sync.RWMutex
	symbolToID   map[string]string
	fallbackName map[string]string
}

func newCoinGeckoClient() *coingeckoClient {
	return &coingeckoClient{
		httpClient: &http.Client{Timeout: 6 * time.Second},
		baseURL:    "https://api.coingecko.com/api/v3",
		symbolToID: map[string]string{
			"BTC":  "bitcoin",
			"ETH":  "ethereum",
			"DOGE": "dogecoin",
		},
		fallbackName: map[string]string{
			"BTC":  "Bitcoin",
			"ETH":  "Ethereum",
			"DOGE": "Dogecoin",
		},
	}
}

func (c *coingeckoClient) resolveID(ctx context.Context, symbol string) (string, error) {
	symbol = normalizeSymbol(symbol)
	c.mu.RLock()
	if id, ok := c.symbolToID[symbol]; ok && id != "" {
		c.mu.RUnlock()
		return id, nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/search?query="+strings.ToLower(symbol), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("coingecko search status %d", resp.StatusCode)
	}
	var parsed struct {
		Coins []struct {
			ID     string `json:"id"`
			Symbol string `json:"symbol"`
		} `json:"coins"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	var found string
	for _, coin := range parsed.Coins {
		if normalizeSymbol(coin.Symbol) == symbol && strings.TrimSpace(coin.ID) != "" {
			found = coin.ID
			break
		}
	}
	if found == "" {
		return "", errors.New("symbol not found")
	}
	c.mu.Lock()
	c.symbolToID[symbol] = found
	c.mu.Unlock()
	return found, nil
}

func (c *coingeckoClient) fetchMarket(ctx context.Context, symbol string) (name string, price float64, updated time.Time, err error) {
	id, err := c.resolveID(ctx, symbol)
	if err == nil {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/coins/markets?vs_currency=usd&ids="+id, nil)
		if reqErr != nil {
			return "", 0, time.Time{}, reqErr
		}
		resp, doErr := c.httpClient.Do(req)
		if doErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var arr []struct {
					Name        string  `json:"name"`
					CurrentPrice float64 `json:"current_price"`
					LastUpdated  string  `json:"last_updated"`
				}
				if decErr := json.NewDecoder(resp.Body).Decode(&arr); decErr == nil && len(arr) > 0 {
					ts, _ := time.Parse(time.RFC3339, arr[0].LastUpdated)
					return arr[0].Name, arr[0].CurrentPrice, ts.UTC(), nil
				}
			}
		}
	}

	sym := normalizeSymbol(symbol)
	c.mu.RLock()
	fname := c.fallbackName[sym]
	c.mu.RUnlock()
	if fname == "" {
		return "", 0, time.Time{}, errors.New("coingecko unavailable")
	}
	now := time.Now().UTC()
	base := map[string]float64{"BTC": 45000.50, "ETH": 2500.25, "DOGE": 0.12}[sym]
	sec := float64(now.Unix()%1000) / 1000.0
	price = math.Round((base*(0.995+0.01*sec))*100) / 100
	return fname, price, now, nil
}

type scheduleState struct {
	Enabled         bool
	IntervalSeconds int
	LastUpdate      time.Time
	NextUpdate      time.Time
}

type scheduler struct {
	mu    sync.Mutex
	state scheduleState

	store *cryptoStore
	cg    *coingeckoClient

	stopCh chan struct{}
	wakeCh chan struct{}
}

func newScheduler(store *cryptoStore, cg *coingeckoClient) *scheduler {
	return &scheduler{
		state: scheduleState{
			Enabled:         true,
			IntervalSeconds: 30,
		},
		store:  store,
		cg:     cg,
		stopCh: make(chan struct{}),
		wakeCh: make(chan struct{}, 1),
	}
}

func (s *scheduler) get() scheduleState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	return st
}

func (s *scheduler) update(enabled *bool, intervalSeconds *int) (scheduleState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if intervalSeconds != nil {
		if *intervalSeconds < 10 || *intervalSeconds > 3600 {
			return scheduleState{}, errors.New("interval_seconds out of range")
		}
		s.state.IntervalSeconds = *intervalSeconds
	}
	if enabled != nil {
		s.state.Enabled = *enabled
	}
	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
	return s.state, nil
}

func (s *scheduler) run(ctx context.Context) {
	var t *time.Ticker
	defer func() {
		if t != nil {
			t.Stop()
		}
	}()
	for {
		s.mu.Lock()
		enabled := s.state.Enabled
		interval := time.Duration(s.state.IntervalSeconds) * time.Second
		s.mu.Unlock()

		if t != nil {
			t.Stop()
		}
		if interval <= 0 {
			interval = 30 * time.Second
		}
		t = time.NewTicker(interval)

		s.mu.Lock()
		if enabled {
			now := time.Now().UTC()
			if s.state.LastUpdate.IsZero() {
				s.state.NextUpdate = now.Add(interval)
			} else {
				s.state.NextUpdate = s.state.LastUpdate.Add(interval)
			}
		} else {
			s.state.NextUpdate = time.Time{}
		}
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-s.wakeCh:
			continue
		case <-t.C:
			if enabled {
				_, _ = s.trigger(ctx)
			}
		}
	}
}

func (s *scheduler) trigger(ctx context.Context) (int, error) {
	cryptos := s.store.list()
	updated := 0
	for _, c := range cryptos {
		name, price, ts, err := s.cg.fetchMarket(ctx, c.Symbol)
		if err != nil {
			continue
		}
		if _, err := s.store.update(c.Symbol, name, price, ts); err == nil {
			updated++
		}
	}
	s.mu.Lock()
	s.state.LastUpdate = time.Now().UTC()
	if s.state.Enabled {
		s.state.NextUpdate = s.state.LastUpdate.Add(time.Duration(s.state.IntervalSeconds) * time.Second)
	} else {
		s.state.NextUpdate = time.Time{}
	}
	s.mu.Unlock()
	return updated, nil
}

type server struct {
	users *userStore
	jwt   *jwtManager
	store *cryptoStore
	cg    *coingeckoClient
	sched *scheduler
}

func newServer() (*server, error) {
	jm, err := newJWTManager()
	if err != nil {
		return nil, err
	}
	us := newUserStore()
	cs := newCryptoStore()
	cg := newCoinGeckoClient()
	sched := newScheduler(cs, cg)
	return &server{
		users: us,
		jwt:   jm,
		store: cs,
		cg:    cg,
		sched: sched,
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/auth/register", s.handleRegister)
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/crypto", s.auth(s.handleCryptoCollection))
	mux.HandleFunc("/crypto/", s.auth(s.handleCryptoItem))
	mux.HandleFunc("/schedule", s.auth(s.handleSchedule))
	mux.HandleFunc("/schedule/trigger", s.auth(s.handleScheduleTrigger))
	return mux
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		if token == "" {
			writeErr(w, http.StatusUnauthorized, "missing token")
			return
		}
		if _, err := s.jwt.parseToken(token); err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{})
}

type authReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req authReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := s.users.create(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errUserExists) {
			writeErr(w, http.StatusConflict, "user already exists")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid credentials")
		return
	}
	token, err := s.jwt.issueToken(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req authReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := s.users.verify(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errBadPassword) || errors.Is(err, errUserNotFound) {
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid credentials")
		return
	}
	token, err := s.jwt.issueToken(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

type addCryptoReq struct {
	Symbol string `json:"symbol"`
}

func (s *server) handleCryptoCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cryptos := s.store.list()
		out := make([]cryptoDTO, 0, len(cryptos))
		for _, c := range cryptos {
			out = append(out, toCryptoDTO(c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"cryptos": out})
	case http.MethodPost:
		var req addCryptoReq
		if err := readJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		sym := normalizeSymbol(req.Symbol)
		if sym == "" {
			writeErr(w, http.StatusBadRequest, "symbol required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		name, price, ts, err := s.cg.fetchMarket(ctx, sym)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to fetch crypto data")
			return
		}
		c := crypto{
			Symbol:       sym,
			Name:         name,
			CurrentPrice: price,
			LastUpdated:  ts.UTC(),
			History:      []historyEntry{{Price: price, Timestamp: ts.UTC()}},
		}
		if err := s.store.add(c); err != nil {
			if errors.Is(err, errCryptoExists) {
				writeErr(w, http.StatusConflict, "crypto already exists")
				return
			}
			writeErr(w, http.StatusInternalServerError, "failed to add crypto")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"crypto": toCryptoDTO(c)})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) handleCryptoItem(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/crypto/")
	path = strings.Trim(path, "/")
	if path == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(path, "/")
	symbol := normalizeSymbol(parts[0])

	if len(parts) == 1 {
		if r.Method != http.MethodGet && r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			c, err := s.store.get(symbol)
			if err != nil {
				writeErr(w, http.StatusNotFound, "crypto not found")
				return
			}
			writeJSON(w, http.StatusOK, toCryptoDTO(c))
			return
		}
		if err := s.store.delete(symbol); err != nil {
			writeErr(w, http.StatusNotFound, "crypto not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	action := parts[1]
	switch action {
	case "refresh":
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		name, price, ts, err := s.cg.fetchMarket(ctx, symbol)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to refresh price")
			return
		}
		updated, err := s.store.update(symbol, name, price, ts)
		if err != nil {
			writeErr(w, http.StatusNotFound, "crypto not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"crypto": toCryptoDTO(updated)})
	case "history":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		c, err := s.store.get(symbol)
		if err != nil {
			writeErr(w, http.StatusNotFound, "crypto not found")
			return
		}
		h := make([]map[string]any, 0, len(c.History))
		for _, e := range c.History {
			h = append(h, map[string]any{
				"price":     e.Price,
				"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"symbol":  symbol,
			"history": h,
		})
	case "stats":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		c, err := s.store.get(symbol)
		if err != nil {
			writeErr(w, http.StatusNotFound, "crypto not found")
			return
		}
		stats := computeStats(c.History)
		writeJSON(w, http.StatusOK, map[string]any{
			"symbol":        symbol,
			"current_price": c.CurrentPrice,
			"stats":         stats,
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func computeStats(h []historyEntry) map[string]any {
	if len(h) == 0 {
		return map[string]any{
			"min_price":            0.0,
			"max_price":            0.0,
			"avg_price":            0.0,
			"price_change":         0.0,
			"price_change_percent": 0.0,
			"records_count":        0,
		}
	}
	minV := h[0].Price
	maxV := h[0].Price
	sum := 0.0
	for _, e := range h {
		if e.Price < minV {
			minV = e.Price
		}
		if e.Price > maxV {
			maxV = e.Price
		}
		sum += e.Price
	}
	avg := sum / float64(len(h))
	first := h[0].Price
	last := h[len(h)-1].Price
	change := last - first
	changePct := 0.0
	if first != 0 {
		changePct = (change / first) * 100.0
	}
	return map[string]any{
		"min_price":            minV,
		"max_price":            maxV,
		"avg_price":            avg,
		"price_change":         change,
		"price_change_percent": changePct,
		"records_count":        len(h),
	}
}

type scheduleUpdateReq struct {
	Enabled         *bool `json:"enabled"`
	IntervalSeconds *int  `json:"interval_seconds"`
}

func (s *server) handleSchedule(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		st := s.sched.get()
		resp := map[string]any{
			"enabled":          st.Enabled,
			"interval_seconds": st.IntervalSeconds,
			"last_update":      "",
			"next_update":      "",
		}
		if !st.LastUpdate.IsZero() {
			resp["last_update"] = st.LastUpdate.UTC().Format(time.RFC3339)
		}
		if !st.NextUpdate.IsZero() {
			resp["next_update"] = st.NextUpdate.UTC().Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		var req scheduleUpdateReq
		if err := readJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		st, err := s.sched.update(req.Enabled, req.IntervalSeconds)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":          st.Enabled,
			"interval_seconds": st.IntervalSeconds,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) handleScheduleTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	updated, err := s.sched.trigger(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "trigger failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"updated_count": updated,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	srv, err := newServer()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.sched.run(ctx)

	httpSrv := &http.Server{
		Addr:              ":8080",
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", httpSrv.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

