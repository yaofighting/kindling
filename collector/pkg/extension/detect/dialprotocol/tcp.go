package dialprotocol

import (
	"context"
	"net"
)

func ExecuteTCP(context context.Context, target string) error {
	var err error

	//
	// Set an explicit timeout
	//
	// d := net.Dialer{}
	d := net.Dialer{}

	//Make the TCP connection.
	conn, err := d.DialContext(context, "tcp", target)
	if err != nil {
		return err
	}

	defer conn.Close()
	return nil
}
