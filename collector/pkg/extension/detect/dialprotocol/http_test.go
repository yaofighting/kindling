package dialprotocol

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestHttpOrHttpsDial(t *testing.T) {
	inputs := []string{
		"http://www.baidu.com:8081/test",
		"http://www.baidu.com",
		"https://www.baidu.com:443/test",
		"http://180.101.50.242:8080/test",
		"www.baidu.com",
		"180.101.50.242/test",
	}

	var arguments = map[string]interface{}{
		"tls":    "insecure",
		"method": "GET",
	}

	for i, v := range inputs {
		ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
		target, err := ParseTarget(v, "http")
		if err != nil {
			fmt.Printf("Illgal Target,Executor http rquest failed: %s\n", inputs[i])
			continue
		}
		if err := ExecuteHTTPRequest(ctx, target, arguments); err != nil {
			fmt.Printf("Executor %s rquest failed: %s\ntarget %+v\nerr :%v\n", target.Scheme, inputs[i], target, err)
		} else {
			fmt.Printf("Executor %s rquest success: %s\ntarget %+v\n", target.Scheme, inputs[i], target)
		}
		fmt.Printf("----------------------------------------\n")
	}
}
