// version: '2022.09.16-rc2'
((
  {
    config,
    debugLogLevel,
    tlsCertChain,
    tlsPrivateKey,
    tlsIssuingCA,
    specEnableEgress,
    inTrafficMatches,
    inClustersConfigs,
    outTrafficMatches,
    outClustersConfigs,
    allowedEndpoints,
    forwardMatches,
    forwardEgressGateways,
    prometheusTarget,
    probeScheme,
    probeTarget,
    probePath,
    logZipkin,
    metrics,
    logLogging
  } = pipy.solve('config.js')) => (

  // Turn On Activity Metrics
  metrics.serverLiveGauge.increase(),

  metrics.tracingAddress &&
  (logZipkin = new logging.JSONLogger('zipkin').toHTTP('http://' + metrics.tracingAddress + metrics.tracingEndpoint, {
    batch: {
      prefix: '[',
      postfix: ']',
      separator: ','
    },
    headers: {
      'Host': metrics.tracingAddress,
      'Content-Type': 'application/json',
    }
  }).log),

  debugLogLevel && (logLogging = new logging.JSONLogger('access-logging').toFile('/dev/stdout').log),

  pipy({
    _dnsSvcAddress: (os.env.DNS_SVC_IP || '10.96.0.10') + ":53"
  })

    .export('main', {
      logZipkin: logZipkin,
      logLogging: logLogging,
      _inMatch: null,
      _inTarget: null,
      _ingressMode: null,
      _inBytesStruct: null,
      _inZipkinData: null,
      _inLoggingData: null,
      _inSessionControl: null,
      _localClusterName: null,
      _outMatch: null,
      _outTarget: null,
      _egressMode: null,
      _egressEndpoint: null,
      _outRequestTime: null,
      _outBytesStruct: null,
      _outZipkinData: null,
      _outLoggingData: null,
      _outIP: null,
      _outPort: null,
      _outSessionControl: null,
      _egressTargetMap: {},
      _upstreamClusterName: null
    })

    //
    // inbound
    //
    .listen(config?.Inbound?.TrafficMatches ? 15003 : 0, {
      'transparent': true
    })
    .onStart(
      () => (
        (() => (
          // Find a match by destination port
          _inMatch = (
            allowedEndpoints?.[__inbound.remoteAddress || '127.0.0.1'] &&
            inTrafficMatches?.[__inbound.destinationPort || 0]
          ),

          // Check client address against the whitelist
          _inMatch?.AllowedEndpoints &&
          _inMatch.AllowedEndpoints[__inbound.remoteAddress] === undefined && (
            _inMatch = null
          ),

          // INGRESS mode
          _ingressMode = _inMatch?.SourceIPRanges?.find?.(e => e.contains(__inbound.remoteAddress)),

          // Layer 4 load balance
          _inTarget = (
            (
              // Allow?
              _inMatch &&
              _inMatch.Protocol !== 'http' && _inMatch.Protocol !== 'grpc'
            ) && (
              // Load balance
              inClustersConfigs?.[
                _localClusterName = _inMatch.TargetClusters?.next?.()?.id
              ]?.next?.()
            )
          ),

          // Session termination control
          _inSessionControl = {
            close: false
          },

          debugLogLevel && (
            console.log('inbound _inMatch: ', _inMatch),
            console.log('inbound _inTarget: ', _inTarget?.id),
            console.log('inbound protocol: ', _inMatch?.Protocol),
            console.log('inbound acceptTLS: ', Boolean(tlsCertChain))
          )
        ))(),
        !_inMatch || (_inTarget && _inMatch.Protocol !== 'http' && _inMatch.Protocol !== 'grpc') ? new Data : null
      )
    )
    .branch(
      () => Boolean(tlsCertChain) && Boolean(_inMatch) && !Boolean(_ingressMode), $ => $
        .acceptTLS({
          certificate: () => ({
            cert: new crypto.Certificate(tlsCertChain),
            key: new crypto.PrivateKey(tlsPrivateKey),
          }),
          trusted: (!tlsIssuingCA && []) || [
            new crypto.Certificate(tlsIssuingCA),
          ]
        }).to($ => $
          .chain(['inbound-recv-tcp.js'])),
      $ => $
        .chain(['inbound-recv-tcp.js'])
    )

    //
    // outbound
    //
    .listen(config?.Outbound || config?.Spec?.Traffic?.EnableEgress ? 15001 : 0, {
      'transparent': true
    })
    .onStart(
      () => (
        ((target) => (
          // Upstream service port
          _outPort = (__inbound.destinationPort || 0),

          // Upstream service IP
          _outIP = (__inbound.destinationAddress || '127.0.0.1'),

          _outMatch = (outTrafficMatches && outTrafficMatches[_outPort] && (
            // Strict matching Destination IP address
            outTrafficMatches[_outPort].find?.(o => (o.DestinationIPRanges && o.DestinationIPRanges.find(e => e.contains(_outIP)))) ||
            // EGRESS mode - does not check the IP
            (_egressMode = true) && outTrafficMatches[_outPort].find?.(o => (!Boolean(o.DestinationIPRanges) &&
              (o.Protocol == 'http' || o.Protocol == 'https' || (o.Protocol == 'tcp' && o.AllowedEgressTraffic))))
          )),

          // Find egress nat gateway
          _outMatch?.EgressForwardGateway && forwardMatches && ((egw) => (
            egw = forwardMatches[_outMatch.EgressForwardGateway]?.next?.()?.id,
            egw && (_egressEndpoint = forwardEgressGateways?.[egw]?.next?.()?.id)
          ))(),

          // Layer 4 load balance
          _outTarget = (
            (
              // Allow?
              _outMatch &&
              _outMatch.Protocol !== 'http' && _outMatch.Protocol !== 'grpc'
            ) && (
              // Load balance
              outClustersConfigs?.[
                _upstreamClusterName = _outMatch.TargetClusters?.next?.()?.id
              ]?.Endpoints?.next?.()
            )
          ),

          // EGRESS mode
          !Boolean(_outTarget) && (specEnableEgress || _outMatch?.AllowedEgressTraffic) && (_outMatch?.Protocol !== 'http' && _outMatch?.Protocol !== 'grpc') && (
            target = _outIP + ':' + _outPort,
            _upstreamClusterName = target,
            !_egressTargetMap[target] && (_egressTargetMap[target] = new algo.RoundRobinLoadBalancer({
              [target]: 100
            })),
            _outTarget = _egressTargetMap[target].next(),
            _egressMode = true
          ),

          _outSessionControl = {
            close: false
          },

          debugLogLevel && (
            console.log('outbound _outMatch: ', _outMatch),
            console.log('outbound _outTarget: ', _outTarget?.id),
            console.log('outbound protocol: ', _outMatch?.Protocol)
          )
        ))(),
        _outTarget && _outMatch?.Protocol !== 'http' && _outMatch?.Protocol !== 'grpc' ? new Data : null
      )
    )
    .branch(
      () => _outMatch?.Protocol === 'http' || _outMatch?.Protocol === 'grpc', $ => $
        .demuxHTTP().to($ => $
          .handleData(
            (data) => (
              _outBytesStruct.requestSize += data.size
            )
          )
          .replaceMessageStart(
            evt => _outSessionControl.close ? new StreamEnd : evt
          )
          .chain(['outbound-recv-http.js'])
          .handleData(
            (data) => (
              _outBytesStruct.responseSize += data.size
            )
          )
          .use(['gather.js'], 'after-upstream-http')
        ),
      () => Boolean(_outTarget), $ => $
        .chain(['outbound-proxy-tcp.js']),
      $ => $
        .replaceStreamStart(
          new StreamEnd('ConnectionReset')
        )
    )

    //
    // Periodic calculate circuit breaker ratio.
    //
    .task('5s')
    .onStart(
      () => new Message
    )
    .replaceMessage(
      () => (
        config.outClustersBreakers && Object.entries(config.outClustersBreakers).map(
          ([k, v]) => (
            v.sample()
          )
        ),
        new StreamEnd
      )
    )

    //
    // liveness probe
    //
    .listen(probeScheme ? 15901 : 0)
    .branch(
      () => probeScheme === 'HTTP', $ => $
        .demuxHTTP().to($ => $
          .handleMessageStart(
            msg => (
              msg.head.path === '/osm-liveness-probe' && (msg.head.path = '/liveness'),
              probePath && (msg.head.path = probePath)
            )
          )
          .muxHTTP(() => probeTarget).to($ => $
            .connect(() => probeTarget)
          )
        ),
      () => Boolean(probeTarget), $ => $
        .connect(() => probeTarget),
      $ => $
        .replaceStreamStart(
          new StreamEnd('ConnectionReset')
        )
    )

    //
    // readiness probe
    //
    .listen(probeScheme ? 15902 : 0)
    .branch(
      () => probeScheme === 'HTTP', $ => $
        .demuxHTTP().to($ => $
          .handleMessageStart(
            msg => (
              msg.head.path === '/osm-readiness-probe' && (msg.head.path = '/readiness'),
              probePath && (msg.head.path = probePath)
            )
          )
          .muxHTTP(() => probeTarget).to($ => $
            .connect(() => probeTarget)
          )
        ),
      () => Boolean(probeTarget), $ => $
        .connect(() => probeTarget),
      $ => $
        .replaceStreamStart(
          new StreamEnd('ConnectionReset')
        )
    )

    //
    // startup probe
    //
    .listen(probeScheme ? 15903 : 0)
    .branch(
      () => probeScheme === 'HTTP', $ => $
        .demuxHTTP().to($ => $
          .handleMessageStart(
            msg => (
              msg.head.path === '/osm-startup-probe' && (msg.head.path = '/startup'),
              probePath && (msg.head.path = probePath)
            )
          )
          .muxHTTP(() => probeTarget).to($ => $
            .connect(() => probeTarget)
          )
        ),
      () => Boolean(probeTarget), $ => $
        .connect(() => probeTarget),
      $ => $
        .replaceStreamStart(
          new StreamEnd('ConnectionReset')
        )
    )

    //
    // Prometheus collects metrics
    //
    .listen(15010)
    .demuxHTTP()
    .to($ => $
      .handleMessageStart(
        msg => (
          (msg.head.path === '/stats/prometheus' && (msg.head.path = '/metrics')) || (msg.head.path = '/stats' + msg.head.path)
        )
      )
      .muxHTTP(() => prometheusTarget)
      .to($ => $
        .connect(() => prometheusTarget)
      )
    )

    //
    // PIPY configuration file and osm get proxy
    //
    .listen(15000)
    .demuxHTTP()
    .to(
      $ => $.chain(['stats.js'])
    )

    //
    // DNS custom response
    //
    .listen('127.0.0.153:5300', {
      protocol: 'udp',
      transparent: true
    })
    .handleStreamStart(
      () => (
        null
        // console.log(__inbound.remoteAddress + ':' + __inbound.remotePort + ' <---> ' + __inbound.destinationAddress + ':' + __inbound.destinationPort)
      )
    )
    .decodeDNS(
      () => (null)
    )
    .handleMessageStart(
      msg => (null)
    )
    .encodeDNS(
      () => (null)
    )
    .connect(() => _dnsSvcAddress, {
      protocol: 'udp'
    })
    .decodeDNS(
      () => (null)
    )
    .handleMessageStart(
      msg => (
        ((name, nsname, fake = false) => (
          (msg.head.qdata[0].qclass == 1 &&
            (msg.head.rcode == 3 || (msg.head.ancount == 0 && msg.head.nscount == 0))) &&
          (
            fake = true,
            name = msg.head.qdata[0].name,
            (msg.head.nscount > 0 && (nsname = msg.head.nsdata[0]?.name)) && (
              // exclude domain suffix : search svc.cluster.local cluster.local
              name.endsWith('.cluster.local') && nsname && (fake = false)
            )
          ),

          // ipv4 : 127.0.0.2
          fake && (msg.head.qdata[0].qtype == 1) && (() => (
            msg.head.qr = 1,
            msg.head.opcode = 0,
            msg.head.aa = 0,
            msg.head.tc = 0,
            msg.head.rd = 1,
            msg.head.ra = 1,
            msg.head.zero = 0,
            msg.head.rcode = 0,
            // msg.head.qcount = 1,
            msg.head.ancount = 1,
            msg.head.nscount = 1,
            msg.head.adcount = 0,
            msg.head.qdata = [{
              "name": name,
              "qtype": 1,
              "qclass": 1
            }],
            msg.head.andata = [{
              "name": name,
              "rtype": 1,
              "rclass": 1,
              "ttl": 5400,
              "length": 4,
              "rdata": {
                "rdata": "127.0.0.2"
              },
              "encoding": 1
            }],
            msg.head.nsdata = [{
              "name": name,
              "rtype": 6,
              "rclass": 1,
              "ttl": 1800,
              "length": 61,
              "rdata": {
                "rdata": {
                  "mname": "a.gtld-servers.net",
                  "rname": "nstld.verisign-grs.com",
                  "serial": 1663232447,
                  "refresh": 1800,
                  "retry": 900,
                  "expire": 604800,
                  "minimum": 86400
                }
              }
            }],
            msg.head.addata = []
          ))(),

          // ipv6 : ::ffff:127.0.0.2
          fake && (msg.head.qdata[0].qtype == 28) && (() => (
            msg.head.qr = 1,
            msg.head.opcode = 0,
            msg.head.aa = 0,
            msg.head.tc = 0,
            msg.head.rd = 1,
            msg.head.ra = 1,
            msg.head.zero = 0,
            msg.head.rcode = 0,
            // msg.head.qcount = 1,
            msg.head.ancount = 1,
            msg.head.nscount = 1,
            msg.head.adcount = 0,
            msg.head.qdata = [{
              "name": name,
              "qtype": 28,
              "qclass": 1
            }],
            msg.head.andata = [{
              "name": name,
              "rtype": 28,
              "rclass": 1,
              "ttl": 5400,
              "length": 16,
              "rdata": {
                "rdata": "00000000000000000000ffff7f000002"
              },
              "encoding": 28
            }],
            msg.head.nsdata = [{
              "name": name,
              "rtype": 6,
              "rclass": 1,
              "ttl": 1800,
              "length": 61,
              "rdata": {
                "rdata": {
                  "mname": "a.gtld-servers.net",
                  "rname": "nstld.verisign-grs.com",
                  "serial": 1663232447,
                  "refresh": 1800,
                  "retry": 900,
                  "expire": 604800,
                  "minimum": 86400
                }
              }
            }],
            msg.head.addata = []
          ))()

        ))()
      )
    )
    .encodeDNS(
      () => (null)
    )

))()

