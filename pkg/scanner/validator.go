package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/core"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/sys"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks" // NEW IMPORT for Shadowsocks
	"github.com/v2fly/v2ray-core/v5/proxy/trojan"
	"github.com/v2fly/v2ray-core/v5/proxy/vless"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tcp"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/websocket"
)

// ProxyConfig represents the parsed proxy configuration for various protocols.
type ProxyConfig struct {
	Protocol    string // e.g., "vless", "trojan", "shadowsocks"
	Address     string
	Port        int
	UserID      string // VLESS/Trojan UUID or Trojan password
	Password    string // Shadowsocks password
	Method      string // Shadowsocks encryption method
	Network     string // e.g., "tcp", "ws", "grpc"
	TLS         bool
	SNI         string
	Path        string // WebSocket path or gRPC service name
	Host        string // HTTP Host header for WebSocket
	Fingerprint string // TLS fingerprint
	// ... other fields for scanner use (e.g., test URL)
}

// ParseProxyURL parses a proxy configuration URL (vless, trojan, ss).
// This function could be refactored into its own `config` package for better SRP,
// but included here to satisfy the "single file" requirement for `codigo_propuesto`.
func ParseProxyURL(rawURL string) (*ProxyConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	cfg := &ProxyConfig{
		Address: u.Hostname(),
		Port: func() int {
			if u.Port() != "" {
				p, _ := strconv.Atoi(u.Port())
				return p
			}
			return 0
		}(),
	}

	switch u.Scheme {
	case "vless":
		cfg.Protocol = "vless"
		cfg.UserID = u.User.Username()
		query := u.Query()
		cfg.Network = query.Get("type")
		cfg.TLS = query.Get("security") == "tls"
		cfg.SNI = query.Get("sni")
		cfg.Path = query.Get("path")
		cfg.Host = query.Get("host")
		cfg.Fingerprint = query.Get("fp")
		if cfg.Port == 0 { cfg.Port = 443 }

	case "trojan":
		cfg.Protocol = "trojan"
		cfg.UserID = u.User.Username()
		cfg.TLS = true
		query := u.Query()
		cfg.SNI = query.Get("sni")
		cfg.Path = query.Get("path")
		cfg.Host = query.Get("host")
		cfg.Network = query.Get("type")
		if cfg.Port == 0 { cfg.Port = 443 }

	case "ss": // Shadowsocks support
		cfg.Protocol = "shadowsocks"
		userInfo := u.User
		if userInfo != nil && userInfo.Username() != "" {
			methodPass := userInfo.Username()
			password, hasPass := userInfo.Password()

			if hasPass {
				cfg.Method = methodPass
				cfg.Password = password
			} else {
				parts := strings.SplitN(methodPass, ":", 2)
				if len(parts) == 2 {
					cfg.Method = parts[0]
					cfg.Password = parts[1]
				} else {
					cfg.Method = methodPass
				}
			}
		} else {
			if len(rawURL) > len("ss://") {
				encodedPart := rawURL[len("ss://"):]
				decoded, err := base64.URLEncoding.DecodeString(encodedPart)
				if err == nil {
					decodedStr := string(decoded)
					parts := strings.SplitN(decodedStr, "@", 2)
					if len(parts) == 2 {
						methodPass := parts[0]
						serverPort := parts[1]

						mpParts := strings.SplitN(methodPass, ":", 2)
						if len(mpParts) == 2 {
							cfg.Method = mpParts[0]
							cfg.Password = mpParts[1]
						} else {
							return nil, fmt.Errorf("invalid Shadowsocks method:password format in base64 payload")
						}

						spParts := strings.SplitN(serverPort, ":", 2)
						if len(spParts) == 2 {
							cfg.Address = spParts[0]
							port, _ := strconv.Atoi(spParts[1])
							cfg.Port = port
						} else {
							return nil, fmt.Errorf("invalid Shadowsocks server:port format in base64 payload")
						}
					} else {
						return nil, fmt.Errorf("invalid Shadowsocks base64 payload format: missing '@'")
					}
				}
			}
		}
		if cfg.Port == 0 { cfg.Port = 8443 }

	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", u.Scheme)
	}

	if cfg.Port == 0 {
		return nil, fmt.Errorf("port not specified and could not be inferred for protocol %s", cfg.Protocol)
	}

	return cfg, nil
}

// Validator handles end-to-end proxy validation using an embedded Xray instance.
type Validator struct {
	xrayInstance *core.Instance
	// ... other fields like logger, context
}

// NewValidator creates a new Validator instance.
func NewValidator() *Validator {
	return &Validator{}
}

// SetupXrayClient configures and starts an embedded Xray instance based on the provided proxy configuration.
// (This is a heavily simplified version, actual Xray configuration requires more detail)
func (v *Validator) SetupXrayClient(cfg *ProxyConfig) (func(), error) {
	if v.xrayInstance != nil {
		v.xrayInstance.Close()
	}

	var proxyOutboundSettings *serial.TypedMessage
	var streamSettings *core.StreamSettings = &core.StreamSettings{
		Network:      core.Network_TCP, // Default network type
		SocketSettings: &core.SocketConfig{
			// Mark: 255, // Example socket option
		},
	}

	if cfg.TLS {
		streamSettings.SecurityType = "tls"
		streamSettings.TlsSettings = &tls.Config{
			ServerName: cfg.SNI,
			// AllowInsecure: true, // Be cautious with this in production
			// Fingerprint: cfg.Fingerprint, // Xray may not directly support simple fingerprint string
		}
	}

	switch cfg.Network {
	case "ws":
		streamSettings.Network = core.Network_WebSocket
		streamSettings.WnSettings = &websocket.ClientConfig{
			Path: cfg.Path,
			Headers: []*websocket.Header{{
				Key: "Host", Value: cfg.Host,
			}},
		}
	case "grpc":
		// Placeholder for gRPC settings if needed
	default:
		streamSettings.Network = core.Network_TCP
		streamSettings.TcpSettings = &tcp.StreamConfig{}
	}


	switch cfg.Protocol {
	case "vless":
		user := &protocol.User{
			Level: 0,
			Email: "love@v2fly.org",
			Account: serial.To(&vless.Account{
				Id: cfg.UserID,
				Flow: "xtls-rprx-vision", // Common for Xray VLESS configs
			}),
		}
		proxyOutboundSettings = serial.To(&vless.ClientConfig{
			User: []*protocol.User{user},
		})

	case "trojan":
		user := &protocol.User{
			Level: 0,
			Account: serial.To(&trojan.Account{
				Password: cfg.UserID,
			}),
		}
		proxyOutboundSettings = serial.To(&trojan.ClientConfig{
			User: []*protocol.User{user},
		})

	case "shadowsocks": // NEW Shadowsocks Xray outbound configuration
		account := &shadowsocks.Account{
			Password: cfg.Password,
			Cipher:   cfg.Method,
			Level:    0,
		}
		user := &protocol.User{
			Level: 0,
			Account: serial.To(account),
		}
		proxyOutboundSettings = serial.To(&shadowsocks.ClientConfig{
			User: []*protocol.User{user},
		})

	default:
		return nil, fmt.Errorf("unsupported proxy protocol for Xray setup: %s", cfg.Protocol)
	}

	xrayCoreConfig := &core.Config{
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "proxy_out",
				ProxySettings: proxyOutboundSettings,
				SenderSettings: &core.SenderSettings{
					StreamSettings: streamSettings,
				},
			},
			{
				Tag: "direct",
				ProxySettings: serial.To(&sys.FreedomConfig{}),
			},
		},
	}

	instance, err := core.New(xrayCoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray instance: %w", err)
	}
	
v.xrayInstance = instance

	if err := v.xrayInstance.Start(); err != nil {
		v.xrayInstance.Close()
		v.xrayInstance = nil
		return nil, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	return func() {
		if v.xrayInstance != nil {
			v.xrayInstance.Close()
			v.xrayInstance = nil
		}
	}, nil
}

// Validate performs a connectivity check through the configured Xray instance.
// This is a placeholder for the actual probing logic.
func (v *Validator) Validate(ctx context.Context, targetIP net.IP, port int) (time.Duration, error) {
	if v.xrayInstance == nil {
		return 0, fmt.Errorf("Xray instance not set up. Call SetupXrayClient first.")
	}
	time.Sleep(150 * time.Millisecond) // Simulate a successful check
	return 150 * time.Millisecond, nil
}