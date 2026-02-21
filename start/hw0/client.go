package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	host             = "localhost"
	port             = "8080"
	expectResponse = "OK\n"
)

func connect() (net.Conn, error) {
	return net.DialTimeout("tcp", host + ":" + port, time.Second)
}

func main() {
	conn, err := connect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}
	if response != expectResponse {
		fmt.Fprintf(os.Stderr, "Invalid server response: expected %q, received %q\n", expectResponse, response)
		os.Exit(1)
	}
}
