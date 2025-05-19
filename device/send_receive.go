/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// ObfuscationType represents the type of obfuscation to be used
type ObfuscationType int

const (
	ObfuscationNone ObfuscationType = iota
	ObfuscationWebSocket
	ObfuscationTLS
)

// ObfuscationConfig holds configuration for traffic obfuscation
type ObfuscationConfig struct {
	Type            ObfuscationType
	ServerAddress   string
	TLSConfig       *tls.Config
	WebSocketConfig *WebSocketConfig
}

// WebSocketConfig holds configuration for WebSocket obfuscation
type WebSocketConfig struct {
	URL          string
	Headers      http.Header
	Subprotocols []string
}

// wrapWithObfuscation wraps a connection with the configured obfuscation
func (device *Device) wrapWithObfuscation(conn net.Conn, config ObfuscationConfig) (net.Conn, error) {
	switch config.Type {
	case ObfuscationWebSocket:
		return device.wrapWithWebSocket(conn, config.WebSocketConfig)
	case ObfuscationTLS:
		return device.wrapWithTLS(conn, config.TLSConfig)
	default:
		// No obfuscation
		return conn, nil
	}
}

// wrapWithWebSocket wraps a connection with WebSocket
func (device *Device) wrapWithWebSocket(conn net.Conn, config *WebSocketConfig) (net.Conn, error) {
	if config == nil {
		config = &WebSocketConfig{
			URL: "wss://localhost/wireguard",
		}
	}
	
	u, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}
	
	// Create a WebSocket dialer
	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Note: In production, this should be properly configured
		},
	}
	
	// Dial the WebSocket server
	wsConn, _, err := dialer.Dial(u.String(), config.Headers)
	if err != nil {
		return nil, err
	}
	
	// Return a net.Conn compatible wrapper
	return &WebSocketConn{
		Conn: wsConn,
	}, nil
}

// wrapWithTLS wraps a connection with TLS encryption
func (device *Device) wrapWithTLS(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, // Note: In production, this should be properly configured
		}
	}
	
	// Create a TLS client
	tlsConn := tls.Client(conn, tlsConfig)
	
	// Perform the TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	
	return tlsConn, nil
}

// WebSocketConn is a wrapper around websocket.Conn that implements net.Conn
type WebSocketConn struct {
	*websocket.Conn
	reader net.Conn
	writer net.Conn
}

// Read implements the net.Conn Read method
func (w *WebSocketConn) Read(b []byte) (n int, err error) {
	// Read from the WebSocket
	messageType, reader, err := w.Conn.NextReader()
	if err != nil {
		return 0, err
	}
	
	if messageType != websocket.BinaryMessage {
		// Skip non-binary messages
		return 0, nil
	}
	
	// Read from the message reader
	return reader.Read(b)
}

// Write implements the net.Conn Write method
func (w *WebSocketConn) Write(b []byte) (n int, err error) {
	// Create a writer for the message
	writer, err := w.Conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	
	// Write the data
	n, err = writer.Write(b)
	if err != nil {
		writer.Close()
		return n, err
	}
	
	// Close the writer to flush the message
	return n, writer.Close()
}

// LocalAddr returns the local network address
func (w *WebSocketConn) LocalAddr() net.Addr {
	if w.Conn != nil && w.Conn.LocalAddr() != nil {
		return w.Conn.LocalAddr()
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr returns the remote network address
func (w *WebSocketConn) RemoteAddr() net.Addr {
	if w.Conn != nil && w.Conn.RemoteAddr() != nil {
		return w.Conn.RemoteAddr()
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline implements the Conn SetDeadline method
func (w *WebSocketConn) SetDeadline(t time.Time) error {
	return w.Conn.SetReadDeadline(t)
}

// SetReadDeadline implements the Conn SetReadDeadline method
func (w *WebSocketConn) SetReadDeadline(t time.Time) error {
	return w.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method
func (w *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return w.Conn.SetWriteDeadline(t)
} 