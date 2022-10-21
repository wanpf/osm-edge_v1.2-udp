// version: '2022.10.21'
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

  pipy({})

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
      _upstreamClusterName: null,
      _outUdpPort: null,
      _outUdpIP: null,
      _outUdpMatch: null,
      _outUdpTarget: null,
      _udpOutRemoteAddressPort: null,
      _udpOutDestinationAddressPort: null,
      _udpHttpsAddressPort: null,
      _udpServiceAddressPort: null
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
    // Proxy for UDP over HTTPS
    //
    .listen(Boolean(tlsCertChain) ? 15005 : 0, { 'transparent': false })
    .onStart(
      () => (
        new Data
      )
    )
    .acceptTLS({
      certificate: () => ({
        cert: new crypto.Certificate(tlsCertChain),
        key: new crypto.PrivateKey(tlsPrivateKey),
      }),
      trusted: (!tlsIssuingCA && []) || [
        new crypto.Certificate(tlsIssuingCA),
      ]
    }).to($ => $
      .demuxHTTP().to($ => $
        .replaceMessage(
          msg => (
            ((udpPort, httpsMatch, httpsTarget) => (
              (msg?.body?.size > 0) && msg?.head?.headers?.['orig-ip-port'] && msg?.head?.headers?.['udp-ip-port'] && (
                udpPort = msg.head.headers['udp-ip-port'].split(':')?.[1],

                // Find a match by destination port
                httpsMatch = (
                  allowedEndpoints?.[__inbound.remoteAddress || '127.0.0.1'] &&
                  inTrafficMatches?.[udpPort]
                ),

                // Check client address against the whitelist
                httpsMatch?.AllowedEndpoints &&
                httpsMatch.AllowedEndpoints[__inbound.remoteAddress] === undefined && (
                  httpsMatch = null
                ),

                // Layer 4 load balance
                httpsTarget = (
                  (
                    // Allow?
                    httpsMatch &&
                    httpsMatch.Protocol === 'udp'
                  ) && (
                    // Load balance
                    inClustersConfigs?.[
                      httpsMatch.TargetClusters?.next?.()?.id
                    ]?.next?.()
                  )
                ),

                Boolean(httpsTarget?.id) && (
                  _udpServiceAddressPort = httpsTarget.id
                ),

                debugLogLevel && (
                  console.log('inbound httpsMatch: ', httpsMatch),
                  console.log('inbound remoteAddress: ', __inbound.remoteAddress),
                  console.log('inbound orig-ip-port: ', msg.head.headers['orig-ip-port']),
                  console.log('inbound udp-ip-port: ', msg.head.headers['udp-ip-port']),
                  console.log('inbound protocol: ', httpsMatch?.Protocol),
                  console.log('inbound _udpServiceAddressPort: ', _udpServiceAddressPort)
                )
              )
            ))(),

            _udpServiceAddressPort ? (
              metrics.udpTlsRxPackageCounter.withLabels(__inbound.remoteAddress, _udpServiceAddressPort).increase(),
              metrics.udpTlsRxBytesCounter.withLabels(__inbound.remoteAddress, _udpServiceAddressPort).increase(msg.body.size),
              new Message({}, msg?.body)
            ) : (_udpServiceAddressPort = '', new StreamEnd)
          )
        )
        .branch(
          () => Boolean(_udpServiceAddressPort) && (_udpServiceAddressPort != ''), $ => $
            .connect(() => _udpServiceAddressPort, {
              protocol: 'udp'
            })
            .replaceMessage(
              msg => (
                msg?.body?.size > 0 ?
                  (metrics.udpTlsTxPackageCounter.withLabels(__inbound.remoteAddress, _udpServiceAddressPort).increase(),
                    metrics.udpTlsTxBytesCounter.withLabels(__inbound.remoteAddress, _udpServiceAddressPort).increase(msg.body.size),
                    new Message({
                      protocol: 'HTTP/1.1',
                      headers: {
                        connection: 'keep-alive'
                      },
                      status: 200,
                      statusText: 'OK'
                    }, msg.body)
                  )
                  : new StreamEnd
              )
            ),
          () => _udpServiceAddressPort === '', $ => $
            .replaceStreamStart(
              new StreamEnd('ConnectionReset')
            )
        )
      )
    )

    //
    // UDP outbound
    //
    .listen(15002, { protocol: 'udp', transparent: true, masquerade: true })
    .onStart(
      () => (
        void (
          // Upstream service port
          _outUdpPort = (__inbound.destinationPort || 0),

          // Upstream service IP
          _outUdpIP = (__inbound.destinationAddress || '127.0.0.1'),

          _outUdpMatch = (outTrafficMatches && outTrafficMatches[_outUdpPort] && (
            // Strict matching Destination IP address
            outTrafficMatches[_outUdpPort].find?.(o => (o.Protocol == 'udp' && o.DestinationIPRanges && o.DestinationIPRanges.find(e => e.contains(_outUdpIP))))
          )),

          // Layer 4 load balance
          _outUdpTarget = (
            (
              // Allow?
              _outUdpMatch
            ) && (
              // Load balance
              outClustersConfigs?.[
                _outUdpMatch.TargetClusters?.next?.()?.id
              ]?.Endpoints?.next?.()
            )
          ),

          Boolean(_outUdpTarget?.id) && (
            _udpHttpsAddressPort = _outUdpTarget?.id.split(':')[0] + ':15005'
          ),

          _udpOutRemoteAddressPort = __inbound.remoteAddress + ':' + __inbound.remotePort,
          _udpOutDestinationAddressPort = __inbound.destinationAddress + ':' + __inbound.destinationPort,

          debugLogLevel && (
            console.log('outbound _outUdpMatch: ', _outUdpMatch),
            console.log('outbound _outUdpTarget: ', _outUdpTarget?.id),
            console.log('outbound protocol: ', _outUdpMatch?.Protocol),
            console.log('outbound _udpHttpsAddressPort: ', _udpHttpsAddressPort),
            console.log('outbound _udpOutRemoteAddressPort: ', _udpOutRemoteAddressPort),
            console.log('outbound _udpOutDestinationAddressPort: ', _udpOutDestinationAddressPort)
          )
        )
      )
    )
    .handleMessage(
      msg => (
        metrics.udpUpstreamTxPackageCounter.withLabels(__inbound.remoteAddress, _udpOutDestinationAddressPort).increase(),
        metrics.udpUpstreamTxBytesCounter.withLabels(__inbound.remoteAddress, _udpOutDestinationAddressPort).increase(msg.body.size)
      )
    )
    .branch(
      () => Boolean(_udpHttpsAddressPort), $ => $
        .replaceMessage(
          msg => new Message({
            method: 'POST',
            path: '/https-for-udp',
            headers: {
              'Host': _udpHttpsAddressPort,
              'Connection': 'keep-alive',
              'Content-Type': 'application/octet-stream',
              'orig-ip-port': _udpOutRemoteAddressPort,
              'udp-ip-port': _outUdpTarget?.id
            }
          }, msg.body)
        )
        .muxHTTP().to($ => $
          .branch(
            () => Boolean(tlsCertChain), $ => $
              .connectTLS({
                certificate: () => ({
                  cert: new crypto.Certificate(tlsCertChain),
                  key: new crypto.PrivateKey(tlsPrivateKey),
                }),
                trusted: (!tlsIssuingCA && []) || [
                  new crypto.Certificate(tlsIssuingCA),
                ]
              }).to($ => $
                .connect(() => _udpHttpsAddressPort)
              )
          )
        )
        .replaceMessage(
          msg => (
            msg?.body?.size > 0 ?
              new Message({}, msg.body) : new StreamEnd
          )
        ),
      $ => $
        .replaceMessage(
          new StreamEnd()
        )
    )

))()