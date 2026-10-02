#include "stunmanager.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QNetworkDatagram>

namespace
{
    QHostAddress firstIPv4Address(const QHostInfo &hostInfo)
    {
        for (const QHostAddress &address : hostInfo.addresses())
        {
            if (address.protocol() == QAbstractSocket::IPv4Protocol)
                return address;
        }

        return {};
    }

    // Splits "host", "host:port" and "[v6-address]:port" (RFC 3986 style).
    void splitHostPort(const QString &value, QString &host, quint16 &port)
    {
        host = value;
        port = 3478;

        if (value.startsWith(u'['))
        {
            const int closingBracket = value.indexOf(u']');
            if (closingBracket == -1)
                return;

            host = value.mid(1, closingBracket - 1);
            const QString remainder = value.mid(closingBracket + 1).trimmed();
            if (remainder.startsWith(u':'))
            {
                bool ok = false;
                const int parsed = remainder.mid(1).toInt(&ok);
                if (ok && (parsed > 0) && (parsed <= 65535))
                    port = static_cast<quint16>(parsed);
            }
            return;
        }

        // A bare IPv6 literal carries several colons and has no port suffix.
        if (value.count(u':') != 1)
            return;

        const int colonIndex = value.indexOf(u':');
        host = value.left(colonIndex);
        bool ok = false;
        const int parsed = value.mid(colonIndex + 1).toInt(&ok);
        if (ok && (parsed > 0) && (parsed <= 65535))
            port = static_cast<quint16>(parsed);
    }

    struct BindingResult
    {
        bool success {false};
        QHostAddress mappedAddress;
        quint16 mappedPort {0};
        QHostAddress otherAddress;
        quint16 otherPort {0};
        bool hasOtherAddress {false};
    };

    // One Binding transaction on an already bound socket. A datagram only counts when
    // it carries this transaction's ID and comes from the address the answer is
    // expected from, so a late reply from an earlier step can never be mistaken for
    // this one.
    BindingResult exchangeBindingRequest(QUdpSocket &socket, const QHostAddress &destination, quint16 destinationPort,
                                         bool changeIP, bool changePort,
                                         const QHostAddress &expectedResponder, quint16 expectedResponderPort,
                                         int timeoutMs)
    {
        BindingResult result;

        const BitTorrent::STUN::TransactionID transactionId = BitTorrent::STUN::TransactionID::generate();
        BitTorrent::STUN::Message request(BitTorrent::STUN::MessageClass::Request, BitTorrent::STUN::Method::Binding, transactionId);
        if (changeIP || changePort)
            request.setChangeRequest(changeIP, changePort);

        socket.writeDatagram(request.serialize(), destination, destinationPort);

        QElapsedTimer timer;
        timer.start();

        while (timer.elapsed() < timeoutMs)
        {
            const int remaining = timeoutMs - static_cast<int>(timer.elapsed());
            if (!socket.waitForReadyRead(qMax(1, remaining)))
                return result;

            while (socket.hasPendingDatagrams())
            {
                const QNetworkDatagram datagram = socket.receiveDatagram();

                BitTorrent::STUN::Message response;
                if (!BitTorrent::STUN::Message::parse(datagram.data(), response))
                    continue;
                if (!response.isSuccessResponse())
                    continue;
                if (response.transactionID() != transactionId)
                    continue;
                if ((datagram.senderAddress() != expectedResponder)
                    || (static_cast<quint16>(datagram.senderPort()) != expectedResponderPort))
                    continue;
                if (!response.hasMappedAddress())
                    continue;

                result.success = true;
                result.mappedAddress = response.mappedAddress();
                result.mappedPort = response.mappedPort();
                if (response.hasOtherAddress() && !response.otherAddress().isNull())
                {
                    result.hasOtherAddress = true;
                    result.otherAddress = response.otherAddress();
                    result.otherPort = (response.otherPort() > 0) ? response.otherPort() : destinationPort;
                }
                return result;
            }
        }

        return result;
    }
}

namespace BitTorrent
{
    // Verified on 2026-10-02 from a CGNAT line in Chongqing. The order matters and is not
    // a latency ranking: the TCP keepalive channel walks the list from the head, and only
    // a server that answers STUN over TCP can report the public TCP port - which is the
    // port this build advertises. So the entries that speak TCP come first. They answer on
    // UDP as well, so the UDP channel loses nothing but the ~100 ms it would have saved.
    // The mainland servers are next (they are the fastest, but none of them speaks STUN
    // over TCP), and the overseas UDP-only ones are last.
    const QStringList STUNManager::DEFAULT_STUN_SERVERS = {
        QStringLiteral("fwa.lifesizecloud.com:3478"),            // UDP+TCP, 126 ms
        QStringLiteral("stun.antisip.com:3478"),                 // UDP+TCP, 233 ms
        QStringLiteral("stunserver2025.stunprotocol.org:3478"),  // UDP+TCP, 270 ms
        QStringLiteral("stun.freeswitch.org:3478"),              // UDP+TCP, 287 ms
        QStringLiteral("stun.douyucdn.cn:18000"),                // UDP only, 18 ms
        QStringLiteral("stun.hitv.com:3478"),                    // UDP only, 31 ms
        QStringLiteral("stun.chat.bilibili.com:3478"),           // UDP only, 45 ms
        QStringLiteral("stun.miwifi.com:3478"),                  // UDP only, 52 ms
        QStringLiteral("stun1.l.google.com:19302"),              // UDP only, 93 ms
        QStringLiteral("stun.cloudflare.com:3478")               // UDP only, 221 ms
    };

    QString natTypeToString(NATType type)
    {
        switch (type)
        {
        case NATType::OpenInternet:
            return QStringLiteral("公网直连 (Open Internet)");
        case NATType::FullCone:
            return QStringLiteral("NAT1 (Full Cone / 全锥形 - 支持公网打洞)");
        case NATType::RestrictedCone:
            return QStringLiteral("NAT2 (Restricted Cone / 受限锥形)");
        case NATType::PortRestrictedCone:
            return QStringLiteral("NAT3 (Port Restricted / 端口受限锥形)");
        case NATType::Symmetric:
            return QStringLiteral("NAT4 (Symmetric / 对称型 - 无法直接穿透)");
        case NATType::UdpBlocked:
            return QStringLiteral("UDP受阻 (UDP Blocked)");
        default:
            return QStringLiteral("未检测 / 未知 (Unknown)");
        }
    }

    QString stunStatusToString(STUNStatus status)
    {
        switch (status)
        {
        case STUNStatus::Disabled:
            return QStringLiteral("已停用");
        case STUNStatus::Resolving:
            return QStringLiteral("解析服务器中...");
        case STUNStatus::Probing:
            return QStringLiteral("探测映射中...");
        case STUNStatus::Mapped:
            return QStringLiteral("穿透成功 (已映射)");
        case STUNStatus::Error:
            return QStringLiteral("连接错误 / 超时");
        default:
            return QStringLiteral("未知状态");
        }
    }

    STUNManager::STUNManager(QObject *parent)
        : QObject(parent)
        , m_serverStrings(DEFAULT_STUN_SERVERS)
    {
        m_natTestPool.setMaxThreadCount(1);

        connect(&m_keepAliveTimer, &QTimer::timeout, this, &STUNManager::onKeepAliveTimeout);
        connect(&m_udpProbeTimer, &QTimer::timeout, this, &STUNManager::onUdpProbeTimeout);
        connect(&m_tcpChannel, &STUNTcpChannel::mapped, this, &STUNManager::onTcpMapped);
        connect(&m_tcpChannel, &STUNTcpChannel::connectFailed, this, &STUNManager::onTcpConnectFailed);
        connect(&m_tcpChannel, &STUNTcpChannel::bindingUnanswered, this, &STUNManager::onTcpBindingUnanswered);

        m_udpProbeTimer.setSingleShot(true);

        parseServerList();
    }

    STUNManager::~STUNManager()
    {
        stop();

        if (m_natTestCancel)
            m_natTestCancel->store(true);

        // The diagnostic runs on a private pool; wait for it so no worker can touch
        // this object after the destructor has run.
        m_natTestPool.waitForDone();
    }

    bool STUNManager::isEnabled() const
    {
        return m_enabled;
    }

    void STUNManager::setEnabled(bool enabled)
    {
        if (m_enabled == enabled)
            return;

        if (enabled)
            start();
        else
            stop();
    }

    quint16 STUNManager::localPort() const
    {
        return m_localPort;
    }

    void STUNManager::setLocalPort(quint16 port)
    {
        if (m_localPort == port)
            return;

        m_localPort = port;
        m_tcpChannel.setLocalPort(port);
        if (m_enabled)
            restart();
    }

    QStringList STUNManager::stunServers() const
    {
        return m_serverStrings;
    }

    void STUNManager::setStunServers(const QStringList &servers)
    {
        m_serverStrings = servers.isEmpty() ? DEFAULT_STUN_SERVERS : servers;
        parseServerList();

        if (m_enabled)
            restart();
    }

    int STUNManager::keepAliveInterval() const
    {
        return m_keepAliveIntervalSec;
    }

    void STUNManager::setKeepAliveInterval(int seconds)
    {
        m_keepAliveIntervalSec = qBound(MIN_KEEPALIVE_INTERVAL_SEC, seconds, MAX_KEEPALIVE_INTERVAL_SEC);

        if (m_keepAliveTimer.isActive())
            m_keepAliveTimer.setInterval(m_keepAliveIntervalSec * 1000);
    }

    bool STUNManager::isUdpKeepAliveEnabled() const
    {
        return m_udpKeepAliveEnabled;
    }

    void STUNManager::setUdpKeepAliveEnabled(bool enabled)
    {
        if (m_udpKeepAliveEnabled == enabled)
            return;

        m_udpKeepAliveEnabled = enabled;

        if (!enabled)
        {
            m_udpFailures = 0;
            closeUdpProbe();
            m_udpProbeTimer.stop();
        }

        // The learned mapping is a fact about the carrier, not about this switch, so it
        // survives being turned off; only what gets announced is recomputed. That keeps
        // the port known if the switch is turned back on later, which is the only way
        // it can still be learned on Windows (see startUdpProbe()).
        updateAnnouncedEndpoint();
        refreshStatus();

        if (m_enabled)
            restart();
    }

    bool STUNManager::isTcpKeepAliveEnabled() const
    {
        return m_tcpKeepAliveEnabled;
    }

    void STUNManager::setTcpKeepAliveEnabled(bool enabled)
    {
        if (m_tcpKeepAliveEnabled == enabled)
            return;

        m_tcpKeepAliveEnabled = enabled;

        if (!enabled)
        {
            m_tcpFailures = 0;
            m_tcpChannel.stop();
        }

        updateAnnouncedEndpoint();
        refreshStatus();

        if (m_enabled)
            restart();
    }

    STUNStatus STUNManager::status() const
    {
        return m_status;
    }

    NATType STUNManager::natType() const
    {
        return m_natType;
    }

    QHostAddress STUNManager::mappedAddress() const
    {
        return m_mappedAddress;
    }

    quint16 STUNManager::mappedPort() const
    {
        return m_mappedPort;
    }

    QHostAddress STUNManager::udpMappedAddress() const
    {
        return m_udpMappedAddress;
    }

    quint16 STUNManager::udpMappedPort() const
    {
        return m_udpMappedPort;
    }

    QHostAddress STUNManager::tcpMappedAddress() const
    {
        return m_tcpMappedAddress;
    }

    quint16 STUNManager::tcpMappedPort() const
    {
        return m_tcpMappedPort;
    }

    bool STUNManager::hasUdpMapping() const
    {
        return m_udpMappedPort > 0;
    }

    bool STUNManager::hasTcpMapping() const
    {
        return m_tcpMappedPort > 0;
    }

    bool STUNManager::isNATTestRunning() const
    {
        return m_natTestRunning;
    }

    bool STUNManager::isTransportEnabled(Transport transport) const
    {
        return (transport == Transport::Udp) ? m_udpKeepAliveEnabled : m_tcpKeepAliveEnabled;
    }

    QString STUNManager::transportName(Transport transport) const
    {
        return (transport == Transport::Udp) ? QStringLiteral("UDP") : QStringLiteral("TCP");
    }

    void STUNManager::start()
    {
        if (m_servers.isEmpty())
            parseServerList();

        if (m_localPort == 0)
        {
            emit logMessage(QStringLiteral("STUN：本地监听端口尚未设置，等待会话初始化。"), true);
            setStatus(STUNStatus::Error);
            return;
        }

        if (!m_udpKeepAliveEnabled && !m_tcpKeepAliveEnabled)
            emit logMessage(QStringLiteral("STUN：UDP 与 TCP 保活均已关闭，穿透不会生效。"), true);

        m_enabled = true;
        m_udpFailures = 0;
        m_tcpFailures = 0;
        m_udpRotations = 0;
        m_udpUnconfirmedLogged = false;

        emit logMessage(QStringLiteral("STUN：保活已启动（本地端口 %1；UDP %2；TCP %3；周期 %4 秒）")
                            .arg(QString::number(m_localPort),
                                 (m_udpKeepAliveEnabled ? QStringLiteral("开") : QStringLiteral("关")),
                                 (m_tcpKeepAliveEnabled ? QStringLiteral("开") : QStringLiteral("关")),
                                 QString::number(m_keepAliveIntervalSec)));

        ensureResolved(Transport::Udp);

        if (m_tcpKeepAliveEnabled)
            ensureResolved(Transport::Tcp);

        m_keepAliveTimer.start(m_keepAliveIntervalSec * 1000);
    }

    void STUNManager::stop()
    {
        stopInternal(true);
    }

    void STUNManager::stopInternal(bool disabledByUser)
    {
        m_enabled = false;
        m_keepAliveTimer.stop();
        abortProbes();

        if (disabledByUser)
            setStatus(STUNStatus::Disabled);
    }

    void STUNManager::restart()
    {
        stopInternal(false);
        start();
    }

    void STUNManager::abortProbes()
    {
        closeUdpProbe();
        m_udpProbeTimer.stop();
        m_tcpChannel.stop();
    }

    bool STUNManager::bindToLocalPort(QAbstractSocket &socket) const
    {
        // ShareAddress keeps the probe from displacing libtorrent's own socket on the
        // same port; the socket only ever lives for the duration of one probe.
        return socket.bind(QHostAddress::AnyIPv4, m_localPort,
                           QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    }

    void STUNManager::parseServerList()
    {
        m_servers.clear();

        for (const QString &item : m_serverStrings)
        {
            const QString trimmed = item.trimmed();
            if (trimmed.isEmpty())
                continue;

            QString host;
            quint16 port = 3478;
            splitHostPort(trimmed, host, port);

            host = host.trimmed();
            if (host.isEmpty())
                continue;

            ServerEndpoint endpoint;
            endpoint.host = host;
            endpoint.port = port;

            const QHostAddress literal(host);
            if (!literal.isNull())
            {
                endpoint.resolvedAddress = literal;
                endpoint.isResolved = true;
            }

            m_servers.append(endpoint);
        }

        m_udpServerIndex = 0;
        m_tcpServerIndex = 0;
    }

    bool STUNManager::resolveEndpointSync(ServerEndpoint &endpoint)
    {
        if (endpoint.isResolved)
            return true;

        const QHostAddress literal(endpoint.host);
        if (!literal.isNull())
        {
            endpoint.resolvedAddress = literal;
            endpoint.isResolved = true;
            return true;
        }

        const QHostInfo hostInfo = QHostInfo::fromName(endpoint.host);
        if (hostInfo.error() != QHostInfo::NoError)
        {
            emit logMessage(QStringLiteral("STUN：解析服务器 [%1] 失败：%2")
                                .arg(endpoint.host, hostInfo.errorString()), true);
            return false;
        }

        const QHostAddress address = firstIPv4Address(hostInfo);
        if (address.isNull())
        {
            emit logMessage(QStringLiteral("STUN：服务器 [%1] 没有可用的 IPv4 地址。").arg(endpoint.host), true);
            return false;
        }

        endpoint.resolvedAddress = address;
        endpoint.isResolved = true;
        return true;
    }

    int &STUNManager::serverIndex(Transport transport)
    {
        return (transport == Transport::Udp) ? m_udpServerIndex : m_tcpServerIndex;
    }

    STUNManager::ServerEndpoint *STUNManager::serverAt(int index)
    {
        if ((index < 0) || (index >= m_servers.size()))
            return nullptr;

        return &m_servers[index];
    }

    STUNManager::ServerEndpoint *STUNManager::currentServer(Transport transport)
    {
        if (m_servers.isEmpty())
            return nullptr;

        int &index = serverIndex(transport);
        if ((index < 0) || (index >= m_servers.size()))
            index = 0;

        return &m_servers[index];
    }

    // The TCP channel skips servers that have already turned out to answer on UDP
    // only; the UDP channel uses every server. Wraps around at most once. When nothing
    // else is left it returns the current index, which the caller reports as "no
    // alternative server" instead of claiming a switch happened.
    int STUNManager::nextServerIndex(Transport transport, int from) const
    {
        const int count = m_servers.size();
        if (count <= 1)
            return 0;

        for (int step = 1; step < count; ++step)
        {
            const int candidate = (from + step) % count;
            if ((transport == Transport::Tcp) && m_servers.at(candidate).tcpRefused)
                continue;

            return candidate;
        }

        return from;
    }

    void STUNManager::ensureResolved(Transport transport)
    {
        if (!m_enabled || !isTransportEnabled(transport))
            return;

        ServerEndpoint *endpoint = currentServer(transport);
        if (!endpoint)
        {
            setStatus(STUNStatus::Error);
            return;
        }

        if (endpoint->isResolved)
        {
            startProbe(transport);
            refreshStatus();
            return;
        }

        setStatus(STUNStatus::Resolving);

        // Resolved per transport with the host captured, so a rotation on one channel
        // cannot make the other channel's answer land on the wrong endpoint.
        const QString host = endpoint->host;
        QHostInfo::lookupHost(host, this, [this, transport, host](const QHostInfo &hostInfo)
        {
            onDnsResolved(transport, host, hostInfo);
        });
    }

    void STUNManager::startProbe(Transport transport)
    {
        if (!m_enabled || !isTransportEnabled(transport))
            return;

        if (transport == Transport::Udp)
        {
            startUdpProbe();
            return;
        }

        const ServerEndpoint *endpoint = currentServer(Transport::Tcp);
        if (!endpoint || !endpoint->isResolved)
        {
            ensureResolved(Transport::Tcp);
            return;
        }

        m_tcpChannel.start(endpoint->resolvedAddress, endpoint->port);
    }

    void STUNManager::onDnsResolved(Transport transport, const QString &host, const QHostInfo &hostInfo)
    {
        if (!m_enabled)
            return;

        ServerEndpoint *endpoint = currentServer(transport);
        if (!endpoint || (endpoint->host != host))
            return;  // the lookup was started before a rotation on this channel

        if (endpoint->isResolved)
            return;

        const QHostAddress address = firstIPv4Address(hostInfo);
        if (address.isNull())
        {
            emit logMessage(QStringLiteral("STUN：解析服务器 [%1] 失败：%2，切换下一台。")
                                .arg(host, hostInfo.errorString()), true);
            scheduleServerAdvance(transport);
            return;
        }

        endpoint->resolvedAddress = address;
        endpoint->isResolved = true;

        startProbe(transport);
        refreshStatus();
    }

    void STUNManager::advanceServer(Transport transport)
    {
        if (!m_enabled)
            return;

        if (m_servers.isEmpty())
        {
            setStatus(STUNStatus::Error);
            return;
        }

        int &index = serverIndex(transport);
        const int previous = index;
        index = nextServerIndex(transport, previous);

        if (transport == Transport::Udp)
            m_udpFailures = 0;
        else
            m_tcpFailures = 0;

        const ServerEndpoint &endpoint = m_servers.at(index);

        if (index == previous)
        {
            // Either a single server is configured, or every alternative is known to be
            // unusable for this transport. Say that rather than claim a switch that did
            // not happen.
            emit logMessage(QStringLiteral("STUN：%1 保活连续失败，但没有其它可用服务器，继续重试 [%2:%3]。")
                                .arg(transportName(transport), endpoint.host)
                                .arg(endpoint.port), true);
        }
        else
        {
            emit logMessage(QStringLiteral("STUN：%1 保活连续失败，切换到备用服务器 [%2:%3]。")
                                .arg(transportName(transport), endpoint.host)
                                .arg(endpoint.port), true);
        }

        // Only this transport's probe is torn down: the channels no longer share a server
        // index, so a TCP rotation must not disturb an in-flight UDP probe.
        if (transport == Transport::Udp)
        {
            closeUdpProbe();
            m_udpProbeTimer.stop();
        }
        else
        {
            m_tcpChannel.stop();
        }

        ensureResolved(transport);
    }

    void STUNManager::scheduleServerAdvance(Transport transport)
    {
        // Deferred: rotating the server destroys sockets, and doing that from inside a
        // socket's own signal handler is not safe.
        QTimer::singleShot(0, this, [this, transport]() { advanceServer(transport); });
    }

    void STUNManager::refreshStatus()
    {
        if (!m_enabled)
        {
            setStatus(STUNStatus::Disabled);
            return;
        }

        // Mapped means "an endpoint this build is keeping alive is being advertised",
        // which is exactly when an announced port exists. A mapping that is merely
        // learned but not maintained does not make the session reachable.
        if (m_mappedPort > 0)
        {
            setStatus(STUNStatus::Mapped);
            return;
        }

        if (m_status == STUNStatus::Resolving)
            return;

        setStatus(STUNStatus::Probing);
    }

    void STUNManager::setStatus(STUNStatus newStatus)
    {
        if (m_status == newStatus)
            return;

        m_status = newStatus;
        emit statusChanged(m_status);
    }

    void STUNManager::updateAnnouncedEndpoint()
    {
        QHostAddress address;
        quint16 port = 0;

        // A tracker announce carries one port, so exactly one transport can ever be
        // advertised. TCP wins when it has a confirmed mapping: its binding exists only
        // because this build holds a connection open from the listening port, whereas
        // the carrier keeps the UDP binding alive on its own. A mapping is only eligible
        // while its keepalive is on, so the announced port is always one that is being
        // refreshed.
        if (m_tcpKeepAliveEnabled && (m_tcpMappedPort > 0))
        {
            address = m_tcpMappedAddress;
            port = m_tcpMappedPort;
        }
        else if (m_udpKeepAliveEnabled && (m_udpMappedPort > 0))
        {
            address = m_udpMappedAddress;
            port = m_udpMappedPort;
        }

        if ((address == m_mappedAddress) && (port == m_mappedPort))
            return;

        m_mappedAddress = address;
        m_mappedPort = port;

        // A port of 0 means nothing is being advertised any more (keepalive disabled or
        // lost), which the session has to hear about as well.
        emit mappedEndpointChanged(address, port);
    }

    void STUNManager::startUdpProbe()
    {
        if (!m_enabled || !m_udpKeepAliveEnabled)
            return;
        if (m_udpPending.active)
            return;  // the previous probe is still in flight

        ServerEndpoint *endpoint = currentServer(Transport::Udp);
        if (!endpoint || !endpoint->isResolved)
        {
            ensureResolved(Transport::Udp);
            return;
        }

        closeUdpProbe();

        m_udpProbe = std::make_unique<QUdpSocket>();
        connect(m_udpProbe.get(), &QUdpSocket::readyRead, this, &STUNManager::onUdpProbeReadyRead);

        if (!bindToLocalPort(*m_udpProbe))
        {
            // Reported loudly on purpose: falling back to an ephemeral port would
            // refresh a mapping nobody uses and still look like success.
            emit logMessage(QStringLiteral("STUN：无法在本地端口 %1 上绑定 UDP 保活套接字（%2）。")
                                .arg(m_localPort)
                                .arg(m_udpProbe->errorString()), true);
            m_udpProbe.reset();
            reportProbeFailure(Transport::Udp, QStringLiteral("无法绑定监听端口"));
            return;
        }

        m_udpPending.active = true;
        m_udpPending.id = BitTorrent::STUN::TransactionID::generate();
        m_udpPending.responderAddress = endpoint->resolvedAddress;
        m_udpPending.responderPort = endpoint->port;

        const BitTorrent::STUN::Message request(BitTorrent::STUN::MessageClass::Request, BitTorrent::STUN::Method::Binding, m_udpPending.id);
        const qint64 written = m_udpProbe->writeDatagram(request.serialize(), endpoint->resolvedAddress, endpoint->port);
        if (written <= 0)
        {
            // Nothing left the machine, so the carrier binding was not refreshed either.
            m_udpPending.active = false;
            m_udpProbe.reset();
            reportProbeFailure(Transport::Udp, QStringLiteral("报文发送失败"));
            return;
        }

        m_udpProbeTimer.start(UDP_PROBE_TIMEOUT_MS);
    }

    void STUNManager::closeUdpProbe()
    {
        m_udpPending.active = false;

        if (m_udpProbe)
        {
            m_udpProbe->disconnect(this);
            m_udpProbe->close();
        }
    }

    void STUNManager::onUdpProbeReadyRead()
    {
        if (!m_udpProbe || !m_udpPending.active)
            return;

        QHostAddress mappedAddress;
        quint16 mappedPort = 0;
        bool resolved = false;

        while (!resolved && m_udpProbe && m_udpProbe->hasPendingDatagrams())
        {
            const QNetworkDatagram datagram = m_udpProbe->receiveDatagram();

            BitTorrent::STUN::Message response;
            if (!BitTorrent::STUN::Message::parse(datagram.data(), response))
                continue;
            if (!response.isSuccessResponse())
                continue;
            if (response.transactionID() != m_udpPending.id)
                continue;
            if ((datagram.senderAddress() != m_udpPending.responderAddress)
                || (static_cast<quint16>(datagram.senderPort()) != m_udpPending.responderPort))
                continue;
            if (!response.hasMappedAddress())
                continue;

            mappedAddress = response.mappedAddress();
            mappedPort = response.mappedPort();
            resolved = true;
        }

        if (resolved)
            finishUdpProbe(true, mappedAddress, mappedPort);
    }

    void STUNManager::onUdpProbeTimeout()
    {
        finishUdpProbe(false);
    }

    void STUNManager::finishUdpProbe(bool success, const QHostAddress &ip, quint16 port)
    {
        closeUdpProbe();
        m_udpProbeTimer.stop();

        if (success)
        {
            reportProbeSuccess(Transport::Udp, ip, port);
            return;
        }

        // Reaching here means the timer fired, and the timer is only started after the
        // datagram was written. The request therefore did leave the listening port, so
        // the carrier binding was refreshed whether or not an answer comes back.
        // Windows hands a unicast reply to whichever socket bound the port first -
        // libtorrent's, not this probe's - so a probe can keep the mapping alive and
        // still never see a response.
        //
        // While the public port is still unknown it is worth walking the list, because a
        // server that does answer is the only way to learn it. That search is bounded by
        // the list; once the list has been walked, silence is reported once and then
        // accepted, instead of rotating servers and warning forever.
        if ((m_udpMappedPort == 0) && (m_udpRotations < m_servers.size()))
        {
            if (++m_udpFailures >= MAX_PROBE_FAILURES)
            {
                ++m_udpRotations;
                m_udpFailures = 0;
                emit logMessage(QStringLiteral("STUN：UDP 保活报文已从监听端口发出但未收到回包，换一台服务器试试。"), true);
                scheduleServerAdvance(Transport::Udp);
            }
            return;
        }

        if (!m_udpUnconfirmedLogged)
        {
            m_udpUnconfirmedLogged = true;
            emit logMessage(QStringLiteral("STUN：UDP 保活报文已从监听端口发出，本机未收到回包"
                                           "（监听端口上的回包由 libtorrent 的套接字接管）。映射以发送维持。"));
        }
    }

    void STUNManager::onTcpMapped(const QHostAddress &ip, quint16 port)
    {
        m_tcpFailures = 0;
        reportProbeSuccess(Transport::Tcp, ip, port);
    }

    void STUNManager::onTcpConnectFailed(const QString &reason)
    {
        // The channel only reports this when the server never answered, so the connection
        // itself is the evidence: refused, timed out, or dropped before any Binding
        // response. Such a server cannot report the public TCP port, and retrying it on
        // every round would cost a full timeout each time.
        if (ServerEndpoint *endpoint = currentServer(Transport::Tcp))
            endpoint->tcpRefused = true;

        reportProbeFailure(Transport::Tcp, reason, true);
    }

    void STUNManager::onTcpBindingUnanswered()
    {
        // Connected, but several Binding Requests in a row went without an answer, so
        // this server does not speak STUN over TCP. Remember that and move on; the
        // mapping learned earlier, if any, stays announced.
        if (ServerEndpoint *endpoint = currentServer(Transport::Tcp))
        {
            endpoint->tcpRefused = true;
            emit logMessage(QStringLiteral("STUN：服务器 [%1:%2] 不接受 TCP 上的 Binding 请求，"
                                           "无法读取 TCP 公网端口，换下一台。")
                                .arg(endpoint->host)
                                .arg(endpoint->port), true);
        }

        scheduleServerAdvance(Transport::Tcp);
    }

    void STUNManager::reportProbeSuccess(Transport transport, const QHostAddress &ip, quint16 port)
    {
        bool changed = false;

        if (transport == Transport::Udp)
        {
            // Both fields are compared: a carrier NAT can move the port while the
            // public IP stays the same, and that must not go unnoticed.
            changed = (m_udpMappedAddress != ip) || (m_udpMappedPort != port);
            m_udpMappedAddress = ip;
            m_udpMappedPort = port;
            m_udpFailures = 0;
        }
        else
        {
            changed = (m_tcpMappedAddress != ip) || (m_tcpMappedPort != port);
            m_tcpMappedAddress = ip;
            m_tcpMappedPort = port;
            m_tcpFailures = 0;
        }

        if (changed)
        {
            emit logMessage(QStringLiteral("STUN：%1 公网映射 %2:%3（本地端口 %4）")
                                .arg(transportName(transport), ip.toString())
                                .arg(port)
                                .arg(m_localPort));
        }

        updateAnnouncedEndpoint();
        refreshStatus();
    }

    void STUNManager::reportProbeFailure(Transport transport, const QString &reason, const bool rotateImmediately)
    {
        int &failures = (transport == Transport::Udp) ? m_udpFailures : m_tcpFailures;
        ++failures;

        emit logMessage(QStringLiteral("STUN：%1 保活失败（%2），连续 %3 次。")
                            .arg(transportName(transport), reason)
                            .arg(failures), true);

        // A UDP heartbeat that was merely not answered is ambiguous (the reply may have
        // gone to libtorrent's socket), so it takes MAX_PROBE_FAILURES rounds before the
        // server is given up on. A TCP connect that never completed is not ambiguous, and
        // walking the list immediately is what keeps the first search short: with a 25 s
        // interval, waiting three rounds per server would take minutes to reach one that
        // speaks STUN over TCP.
        if (rotateImmediately || (failures >= MAX_PROBE_FAILURES))
            scheduleServerAdvance(transport);
    }

    void STUNManager::onKeepAliveTimeout()
    {
        if (!m_enabled || m_servers.isEmpty())
            return;

        startProbe(Transport::Udp);
        startProbe(Transport::Tcp);
        refreshStatus();
    }

    bool STUNManager::discoverMappedPortSync(int timeoutMs)
    {
        if (m_servers.isEmpty())
            parseServerList();

        if (m_servers.isEmpty() || (m_localPort == 0))
            return false;

        // Walk the configured servers so one dead server cannot leave the session
        // announcing a port that is not reachable from the outside.
        for (int attempt = 0; attempt < m_servers.size(); ++attempt)
        {
            ServerEndpoint &endpoint = m_servers[serverIndex(Transport::Udp)];
            if (!resolveEndpointSync(endpoint))
            {
                serverIndex(Transport::Udp) = nextServerIndex(Transport::Udp, serverIndex(Transport::Udp));
                continue;
            }

            QUdpSocket probeSocket;
            if (!probeSocket.bind(QHostAddress::AnyIPv4, m_localPort,
                                  QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
            {
                emit logMessage(QStringLiteral("STUN：无法在本地端口 %1 上绑定探测套接字（%2）。")
                                    .arg(m_localPort)
                                    .arg(probeSocket.errorString()), true);
                return false;
            }

            const BitTorrent::STUN::TransactionID transactionId = BitTorrent::STUN::TransactionID::generate();
            const BitTorrent::STUN::Message request(BitTorrent::STUN::MessageClass::Request, BitTorrent::STUN::Method::Binding, transactionId);
            probeSocket.writeDatagram(request.serialize(), endpoint.resolvedAddress, endpoint.port);

            QElapsedTimer timer;
            timer.start();

            bool finished = false;
            while (!finished && (timer.elapsed() < timeoutMs))
            {
                const int remaining = timeoutMs - static_cast<int>(timer.elapsed());
                if (!probeSocket.waitForReadyRead(qMax(1, remaining)))
                    break;

                while (probeSocket.hasPendingDatagrams())
                {
                    const QNetworkDatagram datagram = probeSocket.receiveDatagram();

                    BitTorrent::STUN::Message response;
                    if (!BitTorrent::STUN::Message::parse(datagram.data(), response))
                        continue;
                    if (!response.isSuccessResponse())
                        continue;
                    if (response.transactionID() != transactionId)
                        continue;
                    if ((datagram.senderAddress() != endpoint.resolvedAddress)
                        || (static_cast<quint16>(datagram.senderPort()) != endpoint.port))
                        continue;
                    if (!response.hasMappedAddress())
                        continue;

                    reportProbeSuccess(Transport::Udp, response.mappedAddress(), response.mappedPort());
                    emit logMessage(QStringLiteral("STUN：已建立公网 UDP 映射 %1:%2（本地端口 %3）")
                                        .arg(response.mappedAddress().toString())
                                        .arg(response.mappedPort())
                                        .arg(m_localPort));
                    finished = true;
                    break;
                }
            }

            if (finished)
                return true;

            emit logMessage(QStringLiteral("STUN：服务器 [%1:%2] 无响应，尝试下一台。")
                                .arg(endpoint.host)
                                .arg(endpoint.port), true);
            serverIndex(Transport::Udp) = nextServerIndex(Transport::Udp, serverIndex(Transport::Udp));
        }

        emit logMessage(QStringLiteral("STUN：所有 STUN 服务器均未响应，未能建立公网映射。"), true);
        return false;
    }

    void STUNManager::runNATTypeTest()
    {
        if (m_natTestRunning)
            return;

        if (m_servers.isEmpty())
            parseServerList();

        if (m_servers.isEmpty())
        {
            emit logMessage(QStringLiteral("STUN：没有可用的 STUN 服务器，无法执行 NAT 诊断。"), true);
            return;
        }

        m_natTestRunning = true;
        m_natTestCancel = std::make_shared<std::atomic_bool>(false);

        const QStringList servers = m_serverStrings;
        const std::shared_ptr<std::atomic_bool> cancel = m_natTestCancel;

        emit logMessage(QStringLiteral("STUN：开始 RFC 5780 NAT 类型诊断…"));

        m_natTestPool.start([this, servers, cancel]()
        {
            NATType detectedType = NATType::Unknown;
            QString detectedDetails;
            bool anyMappingSeen = false;

            for (const QString &item : servers)
            {
                if (cancel->load())
                    return;

                const QString trimmed = item.trimmed();
                if (trimmed.isEmpty())
                    continue;

                QString host;
                quint16 port = 3478;
                splitHostPort(trimmed, host, port);

                host = host.trimmed();
                if (host.isEmpty())
                    continue;

                QHostAddress serverAddress(host);
                if (serverAddress.isNull())
                    serverAddress = firstIPv4Address(QHostInfo::fromName(host));
                if (serverAddress.isNull())
                    continue;

                QUdpSocket socket;
                if (!socket.bind(QHostAddress::AnyIPv4, 0))
                    continue;

                // Test I: what the primary address sees. Tests I and II must run on the
                // same local port, otherwise their mapped ports are not comparable.
                const BindingResult primary = exchangeBindingRequest(socket, serverAddress, port, false, false,
                                                                     serverAddress, port, NAT_TEST_TIMEOUT_MS);
                if (!primary.success)
                    continue;

                anyMappingSeen = true;

                if (!primary.hasOtherAddress)
                {
                    // Without OTHER-ADDRESS there is nothing to compare against and no
                    // way to observe filtering, so this server cannot classify at all.
                    continue;
                }

                // Test II: same local port, different destination -> mapping behaviour.
                const BindingResult secondary = exchangeBindingRequest(socket, primary.otherAddress, primary.otherPort,
                                                                       false, false,
                                                                       primary.otherAddress, primary.otherPort,
                                                                       NAT_TEST_TIMEOUT_MS);
                const bool endpointIndependentMapping = secondary.success
                    && (secondary.mappedAddress == primary.mappedAddress)
                    && (secondary.mappedPort == primary.mappedPort);

                // Test III: change both IP and port. A reply proves the NAT filters on
                // neither; requiring it to come from OTHER-ADDRESS is what proves the
                // server genuinely honoured CHANGE-REQUEST.
                const BindingResult changedBoth = exchangeBindingRequest(socket, serverAddress, port, true, true,
                                                                         primary.otherAddress, primary.otherPort,
                                                                         NAT_TEST_TIMEOUT_MS);

                // Test IV: change the port only.
                const BindingResult changedPort = exchangeBindingRequest(socket, serverAddress, port, false, true,
                                                                         primary.otherAddress, primary.otherPort,
                                                                         NAT_TEST_TIMEOUT_MS);

                const bool serverHonoursChangeRequest = changedBoth.success || changedPort.success;

                if (!endpointIndependentMapping)
                {
                    detectedType = NATType::Symmetric;
                    detectedDetails = QStringLiteral("映射随目标地址变化（对称型 NAT），外部无法直接连入");
                    break;
                }

                if (changedBoth.success)
                {
                    detectedType = NATType::FullCone;
                    detectedDetails = QStringLiteral("映射与过滤均不依赖目标（NAT1 全锥形），外部 Peer 可任意连入");
                }
                else if (changedPort.success)
                {
                    detectedType = NATType::RestrictedCone;
                    detectedDetails = QStringLiteral("映射与目标无关，过滤按来源 IP 限制（NAT2 受限锥形）");
                }
                else
                {
                    detectedType = NATType::PortRestrictedCone;
                    detectedDetails = QStringLiteral("过滤按来源 IP 与端口同时限制（NAT3 端口受限锥形）");
                    if (!serverHonoursChangeRequest)
                        detectedDetails += QStringLiteral("；该服务器未回应 CHANGE-REQUEST，结论仅供参考");
                }

                break;
            }

            if (cancel->load())
                return;

            if (detectedType == NATType::Unknown)
            {
                if (anyMappingSeen)
                {
                    detectedDetails = QStringLiteral("服务器未返回 OTHER-ADDRESS 或未响应 CHANGE-REQUEST，"
                                                     "无法判定映射与过滤行为（不作猜测）");
                }
                else
                {
                    detectedType = NATType::UdpBlocked;
                    detectedDetails = QStringLiteral("所有 STUN 服务器均无响应，UDP 可能被运营商阻断");
                }
            }

            QMetaObject::invokeMethod(this, [this, detectedType, detectedDetails]()
            {
                m_natTestRunning = false;
                m_natType = detectedType;
                emit logMessage(QStringLiteral("STUN：NAT 诊断完成 -> %1：%2")
                                    .arg(natTypeToString(detectedType), detectedDetails));
                emit natTypeDetected(detectedType, detectedDetails);
            }, Qt::QueuedConnection);
        });
    }
}
