package main

import (
	"io"
	"net"
)

const (
	port     = "8080"
	response = "OK\n"
)

func serve(handler net.Listener) {
	defer handler.Close()
	
	for {
		conn, err := handler.Accept()
		if err != nil {
			continue
		}

		defer conn.Close()
		_, _ = io.WriteString(conn, response)
	}
}

func main() {
	handler, err := net.Listen("tcp", ":" + port)
	if err != nil {
		panic(err)
	}
	serve(handler)
}
