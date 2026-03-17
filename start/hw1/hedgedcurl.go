package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultTimeoutSeconds = 15
	timeoutExitCode       = 228
)

type responseResult struct {
	resp *http.Response
	body []byte
	err  error
}

func parseArgs() (timeout time.Duration, urls []string, showClue bool, parseErr error) {
	args := os.Args[1:]

	// быстрая опция, при встреченном -h/--help, без парсинга остального
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return 0, nil, true, nil
		}
	}

	timeoutSeconds := defaultTimeoutSeconds

	// простейший обработчик конфликтов с URL
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-t", "--timeout":
			if i+1 >= len(args) {
				return 0, nil, false, fmt.Errorf("Ожидалось значение после %s", arg)
			}
			i++
			var sec int
			_, err := fmt.Sscanf(args[i], "%d", &sec)
			if err != nil || sec <= 0 {
				return 0, nil, false, fmt.Errorf("Некорректное значение таймаута: %s", args[i])
			}
			timeoutSeconds = sec
		default:
			if len(arg) > 0 && arg[0] == '-' {
				return 0, nil, false, fmt.Errorf("Неизвестный флаг: %s", arg)
			}
			urls = append(urls, arg)
		}
	}
	if len(urls) == 0 {
		return 0, nil, false, fmt.Errorf("Отсутствуют URL")
	}

	return time.Duration(timeoutSeconds) * time.Second, urls, false, nil
}

func printHelpInfo() {
	clue := `hedgedcurl - CLI утилита для хеджированных HTTP-запросов

			Использование:	hedgedcurl [OPTIONS] URL...

			OPTIONS:
			-t, --timeout SECONDS   -> таймаут для всех HTTP запросов (по умолчанию 15)
			-h, --help              -> (текущая) справочная информация
			`
	fmt.Print(clue)
}

func hedgedRequestsPerformance(ctx context.Context, client *http.Client, urls []string) (*http.Response, []byte, error) {
	results := make(chan responseResult, len(urls))

	for _, u := range urls {
		urlStr := u

		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
			if err != nil {
				results <- responseResult{err: err}
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				results <- responseResult{err: err}
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results <- responseResult{err: err}
				return
			}

			results <- responseResult{resp: resp, body: body}
		}()
	}

	var lastErr error

	for i := 0; i < len(urls); i++ {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, nil, ctx.Err()
			}
			return nil, nil, ctx.Err()
		case res := <-results:
			if res.err == nil && res.resp != nil {
				return res.resp, res.body, nil
			}
			lastErr = res.err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("Все запросы завершились ошибкой")
	}

	return nil, nil, lastErr
}

func resopnseFormatToHTTP(resp *http.Response, body []byte) string {
	var headersText string
	for name, values := range resp.Header {
		for _, v := range values {
			headersText += fmt.Sprintf("%s: %s\n", name, v)
		}
	}

	return fmt.Sprintf("%s %s\n%s\n%s", resp.Proto, resp.Status, headersText, string(body))
}

func main() {
	// отключаем стандартный парсер флагов
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	timeout, urls, showClue, err := parseArgs()
	if showClue {
		printHelpInfo()
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		printHelpInfo()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{}

	resp, body, reqErr := hedgedRequestsPerformance(ctx, client, urls)
	if reqErr != nil {
		if errors.Is(reqErr, context.DeadlineExceeded) {
			fmt.Fprintln(os.Stderr, "Ошибка: Превышен таймаут запросов")
			os.Exit(timeoutExitCode)
		}

		fmt.Fprintln(os.Stderr, "Ошибка выполнения запросов:", reqErr)
		os.Exit(1)
	}

	fmt.Print(resopnseFormatToHTTP(resp, body))
}

