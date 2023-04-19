package dialprotocol

import (
	"context"
	"time"

	"github.com/mitchellh/mapstructure"
	probing "github.com/prometheus-community/pro-bing"
)

type ICMPOption struct {
	NeedDetail bool
}

type ICMPReponse struct {
	*probing.Packet
	IsDup bool
}

func ExecuteICMP(ctx context.Context, request DialRequest, pktCh chan<- *ICMPReponse) (*probing.Statistics, error) {
	opt := &ICMPOption{}
	mapstructure.Decode(request.Arguments, opt)

	pinger, err := probing.NewPinger(request.Host)
	if err != nil {
		return nil, err
	}
	go func() {
		for range ctx.Done() {
			pinger.Stop()
		}
	}()

	/* 必须以Root用户运行，否则需要添加启动参数 setcap cap_net_raw=+ep
	   查看 https://github.com/prometheus-community/pro-bing
	*/
	pinger.SetPrivileged(true)
	// 持续一分钟
	// TODO Option
	pinger.Interval = 1 * time.Second
	pinger.Count = 60

	// 单次Packet事件流
	pinger.OnRecv = func(pkt *probing.Packet) {
		if pktCh != nil {
			pktCh <- &ICMPReponse{pkt, false}
		}
	}

	// DUP Packet事件
	pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
		if pktCh != nil {
			pktCh <- &ICMPReponse{pkt, false}
		}
	}

	// 阻塞直到执行完成
	err = pinger.Run()
	if err != nil {
		return nil, err
	} else {
		return pinger.Statistics(), nil
	}
}
