package dialprotocol

import (
	"context"
	"fmt"
	"testing"
)

func TestICMPExecutor(t *testing.T) {
	status, _ := ExecuteICMP(context.Background(), DialRequest{
		SubTaskId: "0",
		Host:      "www.baidu.com",
		Protocol:  ICMP,
		Arguments: nil,
	}, nil)

	fmt.Println(status.Addr)
	fmt.Println(status.IPAddr)
}
