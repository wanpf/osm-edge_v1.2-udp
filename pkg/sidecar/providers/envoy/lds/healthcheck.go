package lds

import (
	"fmt"

	xds_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	xds_health_check "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/health_check/v3"
	xds_hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openservicemesh/osm/pkg/sidecar/providers/envoy"
)

func getHealthCheckFilter() (*xds_hcm.HttpFilter, error) {
	hc := &xds_health_check.HealthCheck{
		PassThroughMode: wrapperspb.Bool(false),
		Headers: []*xds_route.HeaderMatcher{
			{
				Name: ":path",
				HeaderMatchSpecifier: &xds_route.HeaderMatcher_ExactMatch{
					ExactMatch: envoy.EnvoyActiveHealthCheckPath,
				},
			},
			{
				Name: envoy.EnvoyActiveHealthCheckHeaderKey,
				HeaderMatchSpecifier: &xds_route.HeaderMatcher_PresentMatch{
					PresentMatch: true,
				},
			},
		},
	}

	hcAny, err := anypb.New(hc)
	if err != nil {
		return nil, fmt.Errorf("error marshaling health check filter: %w", err)
	}

	return &xds_hcm.HttpFilter{
		Name: envoy.HTTPHealthCheckFilterName,
		ConfigType: &xds_hcm.HttpFilter_TypedConfig{
			TypedConfig: hcAny,
		},
	}, nil
}
