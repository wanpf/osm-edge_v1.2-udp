// version: '2022.10.11'
(
  (config = JSON.decode(pipy.load('config.json')),
    metrics = pipy.solve('metrics.js'),
    breaker = pipy.solve('breaker.js'),
    codeMessage = pipy.solve('codes.js'),
    global
  ) => (

    config.outClustersBreakers = {},
    metrics.sidecarInsideStats = {},

    // pipy inside stats
    metrics.sidecarInsideStats['http_local_rate_limiter.http_local_rate_limit.rate_limited'] = 0,

    global = {
      debugLogLevel: (config?.Spec?.SidecarLogLevel === 'debug'),
      namespace: (os.env.POD_NAMESPACE || 'default'),
      kind: (os.env.POD_CONTROLLER_KIND || 'Deployment'),
      name: (os.env.SERVICE_ACCOUNT || ''),
      pod: (os.env.POD_NAME || ''),
      tlsCertChain: config?.Certificate?.CertChain,
      tlsPrivateKey: config?.Certificate?.PrivateKey,
      tlsIssuingCA: config?.Certificate?.IssuingCA,
      specEnableEgress: null,
      inTrafficMatches: null,
      inClustersConfigs: null,
      outTrafficMatches: null,
      outClustersConfigs: null,
      allowedEndpoints: null,
      prometheusTarget: null,
      probeScheme: null,
      probeTarget: null,
      probePath: null,
      funcShuffle: null,
      forwardMatches: null,
      forwardEgressGateways: null,
      codeMessage: codeMessage,
      mapIssuingCA: {},
      listIssuingCA: []
    },

    global.addIssuingCA = ca => (
      (md5 => (
        md5 = '' + algo.hash(ca),
        !global.mapIssuingCA[md5] && (
          global.listIssuingCA.push(new crypto.Certificate(ca)),
          global.mapIssuingCA[md5] = true
        )
      ))()
    ),

    global.funcShuffle = (arg, out, sort) => (
      arg && (() => (
        sort = a => (a.map(e => e).map(() => a.splice(Math.random() * a.length | 0, 1)[0])),
        global.debugLogLevel && console.log('funcShuffle LB in : ', arg),
        out = Object.fromEntries(sort(sort(Object.entries(arg)))),
        global.debugLogLevel && console.log('funcShuffle LB out : ', out)
      ))(),
      out || {}
    ),

    global.funcCalcScaleRatio = (n) => (
      n < 1 ? 0 : (n = Math.pow(2, n - 1), n > 10 ? 10 : n)
    ),

    global.funcInitLocalRateLimit = (local) => (
      ((burst) => (
        burst = local.Burst > local.Requests ? local.Burst : local.Requests,
        {
          group: algo.uuid(),
          backlog: local.Backlog > 0 ? local.Backlog : 0,
          quota: new algo.Quota(
            burst, {
            produce: local.Requests,
            per: local.StatTimeWindow > 0 ? local.StatTimeWindow : 1
          }
          ),
          status: local.ResponseStatusCode ? local.ResponseStatusCode : 429,
          headers: local.ResponseHeadersToAdd
        }
      ))()
    ),

    global.funcInboundHttpServiceRouteRules = json => (
      Object.fromEntries(Object.entries(json).map(
        ([name, rule]) => [
          name,
          {
            RouteRules: rule?.RouteRules && Object.entries(rule.RouteRules).map(
              ([path, condition], obj) => (
                obj = {
                  Path_: path, // for debugLogLevel
                  Path: new RegExp(path), // HTTP request path
                  Methods: condition.Methods && Object.fromEntries(condition.Methods.map(e => [e, true])),
                  Headers_: condition?.Headers, // for debugLogLevel
                  Headers: condition.Headers && Object.entries(condition.Headers).map(([k, v]) => [k, new RegExp(v)]),
                  AllowedServices: condition.AllowedServices && Object.fromEntries(condition.AllowedServices.map(e => [e, true])),
                  TargetClusters: condition.TargetClusters && new algo.RoundRobinLoadBalancer(global.funcShuffle(condition.TargetClusters)) // Loadbalancer for services
                },
                obj.RateLimit = (condition?.RateLimit?.Local?.Requests > 0) && global.funcInitLocalRateLimit(condition.RateLimit.Local),
                obj
              )
            ),
            RateLimit: (rule?.RateLimit?.Local?.Requests > 0) && global.funcInitLocalRateLimit(rule.RateLimit.Local),
            HeaderRateLimits: rule?.HeaderRateLimits && rule.HeaderRateLimits.map(
              o => ({
                Headers: o.Headers && Object.entries(o.Headers).map(([k, v]) => [k, new RegExp(v)]),
                RateLimit: (o?.RateLimit?.Local?.Requests > 0) && global.funcInitLocalRateLimit(o.RateLimit.Local)
              })
            )
          }
        ]
      ))
    ),

    global.inTrafficMatches = config?.Inbound?.TrafficMatches && Object.fromEntries(
      Object.entries(config.Inbound.TrafficMatches).map(
        ([port, match], obj) => [
          port, // local service port
          (
            obj = {
              Port: match.Port,
              Protocol: match.Protocol,
              HttpHostPort2Service: match.HttpHostPort2Service,
              SourceIPRanges_: match?.SourceIPRanges, // for debugLogLevel
              SourceIPRanges: match.SourceIPRanges && Object.entries(match.SourceIPRanges).map(([k, v]) =>
              ({
                netmask: new Netmask(k),
                mTLS: v?.mTLS,
                skipClientCertValidation: v?.SkipClientCertValidation,
                authenticatedPrincipals: v?.AuthenticatedPrincipals && Object.fromEntries(v.AuthenticatedPrincipals.map(e => [e, true])),
              })),
              TargetClusters: match.TargetClusters && new algo.RoundRobinLoadBalancer(global.funcShuffle(match.TargetClusters)),
              HttpServiceRouteRules: match.HttpServiceRouteRules && global.funcInboundHttpServiceRouteRules(match.HttpServiceRouteRules),
              ProbeTarget: (match.Protocol === 'http') && (!global.probeTarget || !match.SourceIPRanges) && (global.probeTarget = '127.0.0.1:' + port)
            },
            (match?.RateLimit?.Local?.Connections > 0) && (((array) => (
              array = (new Array(match?.RateLimit?.Local?.Connections > 1000 ? 1000 : match?.RateLimit?.Local?.Connections)).fill('connection_').map((e, index) => e + index),
              obj.RateLimit = new algo.LeastWorkLoadBalancer(Object.fromEntries(array.map(k => [k, 1]))),
              obj.RateLimitObject = Object.fromEntries(array.map(k => [k, new String(k)])),
              obj.RateLimitConnQuota = new algo.Quota(
                match?.RateLimit?.Local?.Burst ? match.RateLimit.Local.Burst : match.RateLimit.Local.Connections, {
                produce: match.RateLimit.Local.Connections,
                per: match?.RateLimit?.Local?.StatTimeWindow > 0 ? match.RateLimit.Local.StatTimeWindow : 1
              }
              ),
              obj.RateLimitConnStatsKey = 'local_rate_limit.inbound_' + global.namespace + '/' + global.pod.split('-')[0] + '_' + match.Port + '_' + match.Protocol + '.rate_limited',
              metrics.sidecarInsideStats[obj.RateLimitConnStatsKey] = 0
            ))()),
            obj
          )
        ]
      )
    ),

    global.inClustersConfigs = config?.Inbound?.ClustersConfigs && Object.fromEntries(
      Object.entries(
        config.Inbound.ClustersConfigs).map(
          ([k, v]) => [
            k, (metrics.funcInitClusterNameMetrics(global.namespace, global.kind, global.name, global.pod, k), new algo.RoundRobinLoadBalancer(global.funcShuffle(v)))
          ]
        )
    ),

    global.funcOutboundHttpServiceRouteRules = json => (
      Object.fromEntries(Object.entries(json).map(
        ([name, rule]) => [
          name,
          Object.entries(rule).map(
            ([path, condition]) => ({
              Path_: path, // for debugLogLevel
              Path: new RegExp(path), // HTTP request path
              Methods: condition.Methods && Object.fromEntries(condition.Methods.map(e => [e, true])),
              Headers_: condition?.Headers, // for debugLogLevel
              Headers: condition.Headers && Object.entries(condition.Headers).map(([k, v]) => [k, new RegExp(v)]),
              AllowedServices: condition.AllowedServices && Object.fromEntries(condition.AllowedServices.map(e => [e, true])),
              TargetClusters: condition.TargetClusters && new algo.RoundRobinLoadBalancer(global.funcShuffle(condition.TargetClusters)) // Loadbalancer for services
            })
          )
        ]
      ))
    ),

    global.outTrafficMatches = config?.Outbound?.TrafficMatches && Object.fromEntries(
      Object.entries(config.Outbound.TrafficMatches).map(
        ([port, match]) => [
          port,
          (
            match?.map(
              (o =>
              ({
                Port: o.Port,
                Protocol: o.Protocol,
                ServiceIdentity: o.ServiceIdentity,
                AllowedEgressTraffic: o.AllowedEgressTraffic,
                EgressForwardGateway: o?.EgressForwardGateway,
                HttpHostPort2Service: o.HttpHostPort2Service,
                TargetClusters: o.TargetClusters && new algo.RoundRobinLoadBalancer(global.funcShuffle(o.TargetClusters)),
                DestinationIPRanges: o.DestinationIPRanges && Object.entries(o.DestinationIPRanges).map(
                  ([k, v]) => (
                    v?.SourceCert?.IssuingCA && (
                      global.addIssuingCA(v.SourceCert.IssuingCA)
                    ),
                    {
                      netmask: new Netmask(k),
                      cert: v?.SourceCert?.OsmIssued && global.tlsCertChain && global.tlsPrivateKey ?
                        ({ CertChain: global.tlsCertChain, PrivateKey: global.tlsPrivateKey }) : v?.SourceCert
                    }
                  )
                ),
                HttpServiceRouteRules: o.HttpServiceRouteRules && global.funcOutboundHttpServiceRouteRules(o.HttpServiceRouteRules)
              })
              )
            )
          )
        ]
      )
    ),

    // Loadbalancer for endpoints
    global.outClustersConfigs = config?.Outbound?.ClustersConfigs && Object.fromEntries(
      Object.entries(config.Outbound.ClustersConfigs).map(
        ([k, v]) => (
          v?.ConnectionSettings && (v.ConnectionSettings?.http?.CircuitBreaking?.StatTimeWindow > 0) &&
          (config.outClustersBreakers[k] = breaker(
            k,
            v.ConnectionSettings?.tcp?.MaxConnections,
            v.ConnectionSettings?.http?.MaxRequestsPerConnection,
            v.ConnectionSettings?.http?.MaxPendingRequests,
            v.ConnectionSettings?.http?.CircuitBreaking?.MinRequestAmount,
            v.ConnectionSettings?.http?.CircuitBreaking?.StatTimeWindow,
            v.ConnectionSettings?.http?.CircuitBreaking?.SlowTimeThreshold,
            v.ConnectionSettings?.http?.CircuitBreaking?.SlowAmountThreshold,
            v.ConnectionSettings?.http?.CircuitBreaking?.SlowRatioThreshold,
            v.ConnectionSettings?.http?.CircuitBreaking?.ErrorAmountThreshold,
            v.ConnectionSettings?.http?.CircuitBreaking?.ErrorRatioThreshold,
            v.ConnectionSettings?.http?.CircuitBreaking?.DegradedTimeWindow,
            v.ConnectionSettings?.http?.CircuitBreaking?.DegradedStatusCode,
            v.ConnectionSettings?.http?.CircuitBreaking?.DegradedResponseContent)),
          [
            k, ((obj, array) => (
              obj = {},
              v.ConnectionSettings?.tcp?.MaxConnections && (
                array = (new Array(v.ConnectionSettings?.tcp?.MaxConnections > 1000 ? 1000 : v.ConnectionSettings?.tcp?.MaxConnections)).fill('connection_').map((e, index) => e + index),
                obj.RateLimit = new algo.LeastWorkLoadBalancer(Object.fromEntries(array.map(k => [k, 1]))),
                obj.RateLimitObject = Object.fromEntries(array.map(k => [k, new String(k)])),
                obj.TcpMaxConnections = v.ConnectionSettings.tcp.MaxConnections,
                v.ConnectionSettings?.http?.MaxRequestsPerConnection && (
                  obj.HttpMaxRequestsPerConnection = v.ConnectionSettings.http.MaxRequestsPerConnection
                ),
                v.ConnectionSettings?.http?.MaxPendingRequests && (
                  obj.HttpMaxPendingRequests = v.ConnectionSettings.http.MaxPendingRequests + v.ConnectionSettings.tcp.MaxConnections,
                  obj.HttpMaxPendingStatsKey = 'cluster.' + k + '.upstream_rq_pending_overflow',
                  metrics.sidecarInsideStats[obj.HttpMaxPendingStatsKey] = 0
                )
              ),
              obj.Endpoints = new algo.RoundRobinLoadBalancer(global.funcShuffle(v.Endpoints)),
              v?.SourceCert?.CertChain && v?.SourceCert?.PrivateKey && v?.SourceCert?.IssuingCA && (
                obj.SourceCert = v.SourceCert,
                global.addIssuingCA(v.SourceCert.IssuingCA)
              ),
              v?.SourceCert?.OsmIssued && global.tlsCertChain && global.tlsPrivateKey && (
                obj.SourceCert = { CertChain: global.tlsCertChain, PrivateKey: global.tlsPrivateKey }
              ),
              metrics.funcInitClusterNameMetrics(global.namespace, global.kind, global.name, global.pod, k),
              v.RetryPolicy?.NumRetries && (
                obj.RetryPolicy = {
                  RetryOn: v.RetryPolicy?.RetryOn,
                  lowerbound: v.RetryPolicy?.RetryOn ? v.RetryPolicy.RetryOn.replaceAll('x', '0') : 500,
                  upperbound: v.RetryPolicy?.RetryOn ? v.RetryPolicy.RetryOn.replaceAll('x', '9') : 599,
                  PerTryTimeout: v.RetryPolicy?.PerTryTimeout ? v.RetryPolicy.PerTryTimeout : 1,
                  NumRetries: v.RetryPolicy?.NumRetries ? v.RetryPolicy.NumRetries : 1,
                  RetryBackoffBaseInterval: v.RetryPolicy?.RetryBackoffBaseInterval ? v.RetryPolicy.RetryBackoffBaseInterval : 1,
                  StatsKeyPrefix: 'cluster.' + k + '.upstream_rq_retry'
                }
              ),
              metrics.sidecarInsideStats['cluster.' + k + '.upstream_rq_retry'] = 0,
              metrics.sidecarInsideStats['cluster.' + k + '.upstream_rq_retry_backoff_exponential'] = 0,
              metrics.sidecarInsideStats['cluster.' + k + '.upstream_rq_retry_backoff_ratelimited'] = 0,
              metrics.sidecarInsideStats['cluster.' + k + '.upstream_rq_retry_limit_exceeded'] = 0,
              metrics.sidecarInsideStats['cluster.' + k + '.upstream_rq_retry_overflow'] = 0,
              metrics.sidecarInsideStats['cluster.' + k + '.upstream_rq_retry_success'] = 0,
              obj
            ))()
          ]
        )
      )
    ),

    global.forwardMatches = config?.Forward?.ForwardMatches && Object.fromEntries(
      Object.entries(
        config.Forward.ForwardMatches).map(
          ([k, v]) => [
            k, new algo.RoundRobinLoadBalancer(v || {})
          ]
        )
    ),

    global.forwardEgressGateways = config?.Forward?.EgressGateways && Object.fromEntries(
      Object.entries(
        config.Forward.EgressGateways).map(
          ([k, v]) => [
            k, new algo.RoundRobinLoadBalancer(v?.Endpoints || {})
          ]
        )
    ),

    // Initialize probeScheme, probeTarget, probePath
    config?.Spec?.Probes?.LivenessProbes && config.Spec.Probes.LivenessProbes[0]?.httpGet?.port == 15901 &&
    (global.probeScheme = config.Spec.Probes.LivenessProbes[0].httpGet.scheme) && !global.probeTarget &&
    ((global.probeScheme === 'HTTP' && (global.probeTarget = '127.0.0.1:80')) || (global.probeScheme === 'HTTPS' && (global.probeTarget = '127.0.0.1:443'))) &&
    (global.probePath = '/'),
    // PIPY admin port
    global.prometheusTarget = '127.0.0.1:6060',
    global.allowedEndpoints = config?.AllowedEndpoints,
    global.specEnableEgress = config?.Spec?.Traffic?.EnableEgress,

    global.config = config,
    global.metrics = metrics,

    global.tlsIssuingCA && (
      global.addIssuingCA(global.tlsIssuingCA)
    ),

    global
  )

)()