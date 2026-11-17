package kcfinger

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPClientRoutesHTTPProxy(t *testing.T) {
	t.Parallel()

	requestURL := make(chan string, 1)
	proxyAuth := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL <- r.URL.String()
		proxyAuth <- r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	proxyURL := strings.Replace(proxy.URL, "http://", "http://alice:secret@", 1)
	client, err := NewHTTPClient(proxyURL, false, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get("http://target.invalid/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := <-requestURL; got != "http://target.invalid/path?q=1" {
		t.Fatalf("proxy received URL %q", got)
	}
	if got := <-proxyAuth; got != "Basic YWxpY2U6c2VjcmV0" {
		t.Fatalf("proxy authorization = %q", got)
	}
}

func TestNewHTTPClientRoutesSOCKS5Proxy(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	requestedHost := make(chan string, 1)
	go func() {
		serverErr <- serveOneSOCKS5Request(ln, requestedHost)
	}()

	client, err := NewHTTPClient("socks5://"+ln.Addr().String(), false, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get("http://target.invalid/proxied")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := <-requestedHost; got != "target.invalid" {
		t.Fatalf("SOCKS5 destination = %q", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestNewHTTPClientRejectsInvalidProxy(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"127.0.0.1:8080",
		"ftp://127.0.0.1:21",
		"http://",
		"http://127.0.0.1:8080/path",
		"socks5://127.0.0.1:1080?x=1",
	} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := NewHTTPClient(raw, false, time.Second); err == nil {
				t.Fatalf("NewHTTPClient(%q) succeeded", raw)
			}
		})
	}
}

func TestNewHTTPClientInsecureTLS(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	secureClient, err := NewHTTPClient("", false, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := secureClient.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("verified client accepted a self-signed certificate")
	}

	insecureClient, err := NewHTTPClient("", true, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := insecureClient.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func serveOneSOCKS5Request(ln net.Listener, requestedHost chan<- string) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)

	var greeting [2]byte
	if _, err := io.ReadFull(br, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 {
		return fmt.Errorf("SOCKS version = %d", greeting[0])
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}

	var request [4]byte
	if _, err := io.ReadFull(br, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 {
		return fmt.Errorf("invalid SOCKS5 connect request %v", request)
	}
	host, err := readSOCKS5Host(br, request[3])
	if err != nil {
		return err
	}
	var port [2]byte
	if _, err := io.ReadFull(br, port[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(port[:]) != 80 {
		return fmt.Errorf("destination port = %d", binary.BigEndian.Uint16(port[:]))
	}
	requestedHost <- host

	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return err
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	req.Body.Close()
	if req.URL.Path != "/proxied" {
		return fmt.Errorf("HTTP path = %q", req.URL.Path)
	}
	_, err = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	return err
}

func readSOCKS5Host(r io.Reader, addrType byte) (string, error) {
	switch addrType {
	case 1:
		ip := make([]byte, net.IPv4len)
		_, err := io.ReadFull(r, ip)
		return net.IP(ip).String(), err
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", err
		}
		host := make([]byte, int(size[0]))
		_, err := io.ReadFull(r, host)
		return string(host), err
	case 4:
		ip := make([]byte, net.IPv6len)
		_, err := io.ReadFull(r, ip)
		return net.IP(ip).String(), err
	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type %d", addrType)
	}
}
