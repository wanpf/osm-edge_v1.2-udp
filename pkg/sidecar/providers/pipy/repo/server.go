package repo

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/k8s"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/sidecar/providers/pipy/client"
	"github.com/openservicemesh/osm/pkg/sidecar/providers/pipy/registry"
	"github.com/openservicemesh/osm/pkg/workerpool"
)

const (
	// ServerType is the type identifier for the ADS server
	ServerType = "pipy-Repo"

	// workerPoolSize is the default number of workerpool workers (0 is GOMAXPROCS)
	workerPoolSize = 0

	osmCodebase        = "/osm-edge"
	osmSidecarCodebase = "/osm-edge-sidecar"
	osmCodebaseConfig  = "config.json"
)

// NewRepoServer creates a new Aggregated Discovery Service server
func NewRepoServer(meshCatalog catalog.MeshCataloger, proxyRegistry *registry.ProxyRegistry, _ bool, osmNamespace string,
	cfg configurator.Configurator, certManager *certificate.Manager, kubecontroller k8s.Controller, msgBroker *messaging.Broker) *Server {
	server := Server{
		catalog:        meshCatalog,
		proxyRegistry:  proxyRegistry,
		osmNamespace:   osmNamespace,
		cfg:            cfg,
		certManager:    certManager,
		workQueues:     workerpool.NewWorkerPool(workerPoolSize),
		kubeController: kubecontroller,
		configVerMutex: sync.Mutex{},
		configVersion:  make(map[string]uint64),
		msgBroker:      msgBroker,
		repoClient:     client.NewRepoClient("127.0.0.1", uint16(cfg.GetProxyServerPort())),
	}

	return &server
}

// Start starts the codebase push server
func (s *Server) Start(_ uint32, _ *certificate.Certificate) error {
	// wait until pipy repo is up
	err := wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		success, err := s.repoClient.IsRepoUp()
		if success {
			log.Info().Msg("Repo is READY!")
			return success, nil
		}
		log.Error().Msg("Repo is not up, sleeping ...")
		return success, err
	})
	if err != nil {
		log.Error().Err(err)
	}

	_, err = s.repoClient.Batch(0, []client.Batch{
		{
			Basepath: osmCodebase,
			Items: []client.BatchItem{

				{ Filename: "outbound-tcp-load-balance.js", Content:  codebase_outbound_tcp_load_balance_js },
				{ Filename: "logging-init.js", Content:  codebase_logging_init_js },
				{ Filename: "utils.js", Content:  codebase_utils_js },
				{ Filename: "tracing-init.js", Content:  codebase_tracing_init_js },
				{ Filename: "metrics-http.js", Content:  codebase_metrics_http_js },
				{ Filename: "config.js", Content:  codebase_config_js },
				{ Filename: "tracing.js", Content:  codebase_tracing_js },
				{ Filename: "metrics-init.js", Content:  codebase_metrics_init_js },
				{ Filename: "logging.js", Content:  codebase_logging_js },
				{ Filename: "metrics-tcp.js", Content:  codebase_metrics_tcp_js },
				{ Filename: "inbound-throttle.js", Content:  codebase_inbound_throttle_js },
				{ Filename: "main.js", Content:  codebase_main_js },
				{ Filename: "breaker.js", Content:  codebase_breaker_js },
				{ Filename: "inbound-mux-http.js", Content:  codebase_inbound_mux_http_js },
				{ Filename: "outbound-mux-http.js", Content:  codebase_outbound_mux_http_js },
				{ Filename: "outbound-http-routing.js", Content:  codebase_outbound_http_routing_js },
				{ Filename: "inbound-demux-http.js", Content:  codebase_inbound_demux_http_js },
				{ Filename: "inbound-tls-termination.js", Content:  codebase_inbound_tls_termination_js },
				{ Filename: "outbound-breaker.js", Content:  codebase_outbound_breaker_js },
				{ Filename: "inbound-proxy-tcp.js", Content:  codebase_inbound_proxy_tcp_js },
				{ Filename: "stats.js", Content:  codebase_stats_js },
				{ Filename: "outbound-classifier.js", Content:  codebase_outbound_classifier_js },
				{ Filename: "inbound-http-routing.js", Content:  codebase_inbound_http_routing_js },
				{ Filename: "outbound-proxy-tcp.js", Content:  codebase_outbound_proxy_tcp_js },
				{ Filename: "codes.js", Content:  codebase_codes_js },
				{ Filename: "inbound-classifier.js", Content:  codebase_inbound_classifier_js },
				{ Filename: "inbound-tcp-load-balance.js", Content:  codebase_inbound_tcp_load_balance_js },
				{ Filename: "outbound-demux-http.js", Content:  codebase_outbound_demux_http_js },



				{
					Filename: osmCodebaseConfig,
					Content:  codebaseConfigJSON,
				},

			},
		},
	})
	if err != nil {
		log.Error().Err(err)
	}

	// Start broadcast listener thread
	go s.broadcastListener()

	s.ready = true

	return nil
}

