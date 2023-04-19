package dialprotocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func ExecuteHTTPRequest(ctx context.Context, target HTTPTarget, arguments map[string]interface{}) (err error) {
	//
	// Setup a dialer which will be dual-stack
	//
	dialer := &net.Dialer{
		DualStack: true,
	}

	//
	// This is where some magic happens, we want to connect and do
	// a http check on http://example.com/, but we want to do that
	// via the IP address.
	//
	// We could do that manually by connecting to http://1.2.3.4,
	// and sending the appropriate HTTP Host: header but that risks
	// a bit of complexity with SSL in particular.
	//
	// So instead we fake the address in the dialer object, so that
	// we don't rewrite anything, don't do anything manually, and
	// instead just connect to the right IP by magic.
	//
	//lint:ignore SA4009 we're deliberately forcing a specific IPv4 vs. IPv6 address
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		//
		// Assume an IPv4 address by default.
		//
		addr = fmt.Sprintf("%s:%s", target.Ip, target.Port)

		//
		// If we find a ":" we know it is an IPv6 address though
		//
		if strings.Contains(target.Ip, ":") {
			addr = fmt.Sprintf("[%s]:%s", target.Ip, target.Port)
		}

		//
		// Use the replaced/updated address in our connection.
		//
		return dialer.DialContext(ctx, network, addr)
	}

	//
	// Create a context which uses the dial-context
	//
	// The dial-context is where the magic happens.
	//
	tr := &http.Transport{
		DialContext: dial,
	}

	//
	// If we're running insecurely then ignore SSL errors
	//
	if arguments["tls"] == "insecure" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	//
	// Create a client with a timeout, disabled redirection, and
	// the magical transport we've just created.
	//
	var netClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}

	var req *http.Request

	//
	// The default method is "GET"
	//
	method := "GET"

	//
	// That can be changed
	//
	if arguments["method"] != nil {
		method = arguments["method"].(string)
	}

	//
	// If we have no data then make a GET request
	//
	if arguments["data"] == nil {
		req, err = http.NewRequestWithContext(ctx, method, target.RawTarget, nil)
	} else {

		//
		// Otherwise make a HTTP POST request, with
		// the specified data.
		//
		req, err = http.NewRequestWithContext(ctx, method, target.RawTarget,
			bytes.NewBuffer([]byte(arguments["data"].(string))))
	}
	if err != nil {
		return err
	}

	//
	// Are we using basic-auth?
	//
	if arguments["username"] != "" {
		req.SetBasicAuth(arguments["username"].(string),
			arguments["password"].(string))
	}

	//
	// Set a suitable user-agent
	//
	if arguments["user-agent"] != "" {
		req.Header.Set("User-Agent", arguments["user-agent"].(string))
	} else {
		req.Header.Set("User-Agent", "overseer/probe")
	}

	//
	// Perform the request
	//
	response, err := netClient.Do(req)
	if err != nil {
		return err
	}

	//
	// Get the body and status-code.
	//
	defer response.Body.Close()
	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	fmt.Printf("url: %s\n", response.Request.URL)
	return nil
}

func ipv4Addr(host string) (string, error) {
	ips, err := net.LookupIP(host)

	if err != nil {
		return "", fmt.Errorf("resolve Dns Error")
	}

	// select one ipv4
	var targetIp string
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIp = ip.String()
			break
		}
		if ip.To16() != nil && ip.To4() == nil {
			targetIp = ip.String()
			break
		}
	}
	return targetIp, nil
}

type HTTPTarget struct {
	Scheme    string
	Host      string
	Port      string
	Ip        string
	RawTarget string
}

func ParseTarget(rawString string, Scheme string) (target HTTPTarget, err error) {
	target = HTTPTarget{
		Scheme: Scheme,
		Host:   rawString,
		Port:   "80",
		Ip:     "",
	}
	if !strings.Contains(rawString, "://") {
		rawString = fmt.Sprintf("%s://%s", Scheme, rawString)
	}
	var u *url.URL
	u, err = url.Parse(rawString)
	if err != nil {
		// 非法地址
		return
	}
	target.Host = u.Hostname()
	target.Scheme = u.Scheme
	if u.Scheme == "http" {
		target.Port = "80"
	}
	if u.Scheme == "https" {
		target.Port = "443"
	}
	if u.Port() != "" {
		target.Port = u.Port()
	}

	target.Ip, err = ipv4Addr(target.Host)
	target.RawTarget = rawString
	return
}
