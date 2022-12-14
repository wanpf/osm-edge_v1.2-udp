package driver

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/openservicemesh/osm/pkg/sidecar/providers/envoy"
	"github.com/openservicemesh/osm/pkg/sidecar/providers/envoy/ads"
)

func (sd EnvoySidecarDriver) getXDSHandler(xdsServer *ads.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xdsLog := xdsServer.GetXDSLog()

		var proxies []string
		for proxyID := range xdsLog {
			proxies = append(proxies, proxyID)
		}

		sort.Strings(proxies)

		for _, proxyName := range proxies {
			xdsTypeWithTimestamps := xdsLog[proxyName]
			_, _ = fmt.Fprintf(w, "---[ %s\n", proxyName)

			var xdsTypes []string
			for xdsType := range xdsTypeWithTimestamps {
				xdsTypes = append(xdsTypes, xdsType.String())
			}

			sort.Strings(xdsTypes)

			for _, xdsType := range xdsTypes {
				timeStamps := xdsTypeWithTimestamps[envoy.TypeURI(xdsType)]

				_, _ = fmt.Fprintf(w, "\t %s (%d):\n", xdsType, len(timeStamps))

				sort.Slice(timeStamps, func(i, j int) bool {
					return timeStamps[i].After(timeStamps[j])
				})
				for _, timeStamp := range timeStamps {
					_, _ = fmt.Fprintf(w, "\t\t%+v (%+v ago)\n", timeStamp, time.Since(timeStamp))
				}
				_, _ = fmt.Fprint(w, "\n")
			}
			_, _ = fmt.Fprint(w, "\n")
		}
	})
}
