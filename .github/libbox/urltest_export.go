package libbox

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func URLTestOutbound(configContent string, outboundTag string, testURL string, timeout int32) (int32, error) {
	return urlTestOutbound(configContent, outboundTag, testURL, timeout, nil)
}

func URLTestOutboundWithPlatform(configContent string, outboundTag string, testURL string, timeout int32, platformInterface PlatformInterface) (int32, error) {
	return urlTestOutbound(configContent, outboundTag, testURL, timeout, platformInterface)
}

type urlTestPlatformInterface struct {
	*platformInterfaceStub
	platformInterface PlatformInterface
}

func (i *urlTestPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool {
	return true
}

func (i *urlTestPlatformInterface) AutoDetectInterfaceControl(fd int) error {
	return i.platformInterface.AutoDetectInterfaceControl(int32(fd))
}

func (i *urlTestPlatformInterface) UsePlatformDefaultInterfaceMonitor() bool {
	return false
}

func urlTestOutbound(configContent string, outboundTag string, testURL string, timeout int32, platformInterface PlatformInterface) (int32, error) {
	ctx := baseContext(platformInterface)
	if platformInterface != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, &urlTestPlatformInterface{
			platformInterfaceStub: &platformInterfaceStub{},
			platformInterface:     platformInterface,
		})
	}
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return 0, E.Cause(err, "parse config")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if outboundTag == "" {
		outboundTag = "proxy"
	}
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	options.Route.Final = outboundTag

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return 0, E.Cause(err, "create box")
	}
	defer instance.Close()

	if err = instance.Start(); err != nil {
		return 0, E.Cause(err, "start box")
	}

	outbound, loaded := instance.Outbound().Outbound(outboundTag)
	if !loaded || outbound == nil {
		outbound = instance.Outbound().Default()
	}
	if outbound == nil {
		return 0, E.New("outbound not available: ", outboundTag)
	}

	testCtx := ctx
	if timeout > 0 {
		var timeoutCancel context.CancelFunc
		testCtx, timeoutCancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer timeoutCancel()
	}

	if testURL == "" {
		testURL = "http://cp.cloudflare.com/"
	}
	delay, err := urltest.URLTest(testCtx, testURL, outbound)
	if err != nil {
		return 0, E.Cause(err, "perform url test")
	}
	return int32(delay), nil
}

var outboundStatsClient struct {
	sync.Mutex
	address string
	conn    *grpc.ClientConn
}

func getOutboundStatsConnection(apiAddress string) (*grpc.ClientConn, error) {
	outboundStatsClient.Lock()
	defer outboundStatsClient.Unlock()
	if outboundStatsClient.conn != nil && outboundStatsClient.address == apiAddress {
		return outboundStatsClient.conn, nil
	}
	if outboundStatsClient.conn != nil {
		_ = outboundStatsClient.conn.Close()
	}
	conn, err := grpc.NewClient(
		apiAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		outboundStatsClient.address = ""
		outboundStatsClient.conn = nil
		return nil, err
	}
	outboundStatsClient.address = apiAddress
	outboundStatsClient.conn = conn
	return conn, nil
}

func invalidateOutboundStatsConnection(conn *grpc.ClientConn) {
	outboundStatsClient.Lock()
	defer outboundStatsClient.Unlock()
	if outboundStatsClient.conn != conn {
		return
	}
	_ = outboundStatsClient.conn.Close()
	outboundStatsClient.address = ""
	outboundStatsClient.conn = nil
}

func CloseV2RayOutboundStats() {
	outboundStatsClient.Lock()
	defer outboundStatsClient.Unlock()
	if outboundStatsClient.conn != nil {
		_ = outboundStatsClient.conn.Close()
	}
	outboundStatsClient.address = ""
	outboundStatsClient.conn = nil
}

func QueryV2RayOutboundStats(apiAddress string, outboundTags string) (string, error) {
	if apiAddress == "" {
		return "", E.New("empty v2ray api address")
	}

	conn, err := getOutboundStatsConnection(apiAddress)
	if err != nil {
		return "", E.Cause(err, "dial v2ray api")
	}

	patterns := make([]string, 0)
	for _, tag := range strings.Split(outboundTags, ",") {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		patterns = append(patterns, "outbound>>>"+trimmed+">>>traffic")
	}
	if len(patterns) == 0 {
		patterns = append(patterns, "outbound>>>proxy>>>traffic")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	request := &v2rayapi.QueryStatsRequest{
		Patterns: patterns,
	}
	response := new(v2rayapi.QueryStatsResponse)
	err = conn.Invoke(
		ctx,
		"/v2ray.core.app.stats.command.StatsService/QueryStats",
		request,
		response,
	)
	if err != nil {
		invalidateOutboundStatsConnection(conn)
		return "", E.Cause(err, "query stats")
	}

	var upload int64
	var download int64
	for _, stat := range response.GetStat() {
		switch {
		case strings.HasSuffix(stat.GetName(), ">>>uplink"):
			upload += stat.GetValue()
		case strings.HasSuffix(stat.GetName(), ">>>downlink"):
			download += stat.GetValue()
		}
	}

	return fmt.Sprintf("%d,%d", upload, download), nil
}
