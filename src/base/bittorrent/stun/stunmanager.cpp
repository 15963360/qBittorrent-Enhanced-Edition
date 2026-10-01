#include "stunmanager.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QNetworkDatagram>
#include <QtEndian>

namespace
{
    // A STUN message larger than this over TCP means we lost framing; drop the
    // connection rather than accumulating an unbounded buffer.
    constexpr int MAX_TCP_FRAME_BYTES = 4096;

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

    // STUN over TCP (RFC 5389 7.2.2) is framed by the length field in its own header.
    // Returns -1 while the header itself is still incomplete.
    int stunFrameSize(const QByteArray &buffer)
    {
        if (buffer.size() < BitTorrent::STUN::HEADER_SIZE)
            return -1;

        const quint16 bodyLength = qFromBigEndian<quint16>(
            reinterpret_cast<const uchar *>(buffer.constData()) + 2);
        return BitTorrent::STUN::HEADER_SIZE + bodyLength;
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
    const QStringList STUNManager::DEFAULT_STUN_SERVERS = {
        QStringLiteral("stun.miwifi.com:3478"),
        QStringLiteral("stun.douyucdn.cn:18000"),
        QStringLiteral("stun.chat.bilibili.com:3478"),
        QStringLiteral("stun.hitv.com:3478"),
        QStringLiteral("stun.cloudflare.com:3478"),
        QStringLiteral("stun1.l.google.com:19302"),
        QStringLiteral("stun.syncthing.net:3478")
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
        connect(&m_tcpProbeTimer, &QTimer::timeout, this, &STUNManager::onTcpProbeTimeout);

        m_udpProbeTimer.setSingleShot(true);
        m_tcpProbeTimer.setSingleShot(true);

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
            m_udpMappedAddress.clear();
            m_udpMappedPort = 0;
            m_udpFailures = 0;
            closeUdpProbe();
            updateAnnouncedEndpoint();
        }

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
            m_tcpMappedAddress.clear();
            m_tcpMappedPort = 0;
            m_tcpFailures = 0;
            m_tcpServerAnswered = false;
            m_tcpUnsupportedWarned = false;
            closeTcpProbe();
            updateAnnouncedEndpoint();
        }

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
        closeTcpProbe();
        m_udpProbeTimer.stop();
        m_tcpProbeTimer.stop();
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

        m_currentServerIndex = 0;
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

    STUNManager::ServerEndpoint *STUNManager::currentServer()
    {
        if (m_servers.isEmpty() || (m_currentServerIndex < 0) || (m_currentServerIndex >= m_servers.size()))
            return nullptr;

        return &m_servers[m_currentServerIndex];
    }

    void STUNManager::ensureResolved(Transport transport)
    {
        if (!m_enabled || !isTransportEnabled(transport))
            return;

        ServerEndpoint *endpoint = currentServer();
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
        QHostInfo::lookupHost(endpoint->host, this, &STUNManager::onDnsResolved);
    }

    void STUNManager::startProbe(Transport transport)
    {
        if (!m_enabled || !isTransportEnabled(transport))
            return;

        if (transport == Transport::Udp)
            startUdpProbe();
        else
            startTcpProbe();
    }

    void STUNManager::onDnsResolved(const QHostInfo &hostInfo)
    {
        if (!m_enabled || m_servers.isEmpty())
            return;

        if ((m_currentServerIndex < 0) || (m_currentServerIndex >= m_servers.size()))
            return;

        ServerEndpoint &endpoint = m_servers[m_currentServerIndex];
        if (hostInfo.hostName() != endpoint.host)
            return;  // a lookup that was started before a server switch

        if (endpoint.isResolved)
            return;

        const QHostAddress address = firstIPv4Address(hostInfo);
        if (address.isNull())
        {
            emit logMessage(QStringLiteral("STUN：解析服务器 [%1] 失败：%2，切换备用服务器。")
                                .arg(endpoint.host, hostInfo.errorString()), true);
            scheduleServerAdvance(Transport::Udp);
            return;
        }

        endpoint.resolvedAddress = address;
        endpoint.isResolved = true;

        startProbe(Transport::Udp);
        startProbe(Transport::Tcp);
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

        m_currentServerIndex = (m_currentServerIndex + 1) % m_servers.size();
        m_udpFailures = 0;
        m_tcpFailures = 0;

        const ServerEndpoint &endpoint = m_servers.at(m_currentServerIndex);
        emit logMessage(QStringLiteral("STUN：%1 保活连续失败，切换到备用服务器 [%2:%3]。")
                            .arg(transportName(transport), endpoint.host)
                            .arg(endpoint.port), true);

        abortProbes();
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

        if (hasUdpMapping() || hasTcpMapping())
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

        if (m_udpMappedPort > 0)
        {
            address = m_udpMappedAddress;
            port = m_udpMappedPort;
        }
        else if (m_tcpMappedPort > 0)
        {
            address = m_tcpMappedAddress;
            port = m_tcpMappedPort;
        }

        if ((address == m_mappedAddress) && (port == m_mappedPort))
            return;

        m_mappedAddress = address;
        m_mappedPort = port;

        // A port of 0 means the mapping is gone (keepalive disabled or lost), which
        // the session has to hear about as well.
        emit mappedEndpointChanged(address, port);
    }

    void STUNManager::startUdpProbe()
    {
        if (!m_enabled || !m_udpKeepAliveEnabled)
            return;
        if (m_udpPending.active)
            return;  // the previous probe is still in flight

        ServerEndpoint *endpoint = currentServer();
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
            ++m_udpFailures;
            refreshStatus();
            return;
        }

        m_udpPending.active = true;
        m_udpPending.id = BitTorrent::STUN::TransactionID::generate();
        m_udpPending.responderAddress = endpoint->resolvedAddress;
        m_udpPending.responderPort = endpoint->port;

        const BitTorrent::STUN::Message request(BitTorrent::STUN::MessageClass::Request, BitTorrent::STUN::Method::Binding, m_udpPending.id);
        m_udpProbe->writeDatagram(request.serialize(), endpoint->resolvedAddress, endpoint->port);
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

        if (!success)
        {
            reportProbeFailure(Transport::Udp, QStringLiteral("探测超时，未收到响应"));
            return;
        }

        reportProbeSuccess(Transport::Udp, ip, port);
    }

    void STUNManager::startTcpProbe()
    {
        if (!m_enabled || !m_tcpKeepAliveEnabled)
            return;

        ServerEndpoint *endpoint = currentServer();
        if (!endpoint || !endpoint->isResolved)
        {
            ensureResolved(Transport::Tcp);
            return;
        }

        if (m_tcpSocket)
        {
            // An attempt is already in flight; let it finish or time out.
            if (m_tcpSocket->state() == QAbstractSocket::ConnectingState)
                return;

            if (m_tcpSocket->state() == QAbstractSocket::ConnectedState)
            {
                const bool sameServer = (m_tcpServerAddress == endpoint->resolvedAddress)
                                        && (m_tcpServerPort == endpoint->port);
                if (sameServer)
                {
                    sendTcpBindingRequest();  // keep the binding warm on the open connection
                    return;
                }
            }
        }

        // A carrier NAT ties the TCP binding to the source port of the SYN, so every
        // new attempt has to leave from the listening port again. The socket is
        // rebuilt instead of reused, because abort() also drops the bind.
        closeTcpProbe();

        m_tcpSocket = std::make_unique<QTcpSocket>();
        connect(m_tcpSocket.get(), &QTcpSocket::connected, this, &STUNManager::onTcpConnected);
        connect(m_tcpSocket.get(), &QTcpSocket::readyRead, this, &STUNManager::onTcpReadyRead);
        connect(m_tcpSocket.get(), &QTcpSocket::errorOccurred, this, &STUNManager::onTcpSocketError);

        if (!bindToLocalPort(*m_tcpSocket))
        {
            emit logMessage(QStringLiteral("STUN：无法在本地端口 %1 上绑定 TCP 保活套接字（%2）。")
                                .arg(m_localPort)
                                .arg(m_tcpSocket->errorString()), true);
            m_tcpSocket.reset();
            ++m_tcpFailures;
            refreshStatus();
            return;
        }

        m_tcpServerAddress = endpoint->resolvedAddress;
        m_tcpServerPort = endpoint->port;
        m_tcpBuffer.clear();
        m_tcpServerAnswered = false;
        m_tcpUnsupportedWarned = false;

        m_tcpSocket->connectToHost(endpoint->resolvedAddress, endpoint->port);
        m_tcpProbeTimer.start(TCP_PROBE_TIMEOUT_MS);
        refreshStatus();
    }

    void STUNManager::closeTcpProbe()
    {
        m_tcpPending.active = false;
        m_tcpBuffer.clear();

        if (m_tcpSocket)
        {
            m_tcpSocket->disconnect(this);
            m_tcpSocket->abort();
        }
    }

    void STUNManager::onTcpConnected()
    {
        m_tcpBuffer.clear();
        m_tcpServerAnswered = false;
        sendTcpBindingRequest();
    }

    void STUNManager::sendTcpBindingRequest()
    {
        if (!m_tcpSocket || (m_tcpSocket->state() != QAbstractSocket::ConnectedState))
            return;

        m_tcpPending.active = true;
        m_tcpPending.id = BitTorrent::STUN::TransactionID::generate();
        m_tcpPending.responderAddress = m_tcpServerAddress;
        m_tcpPending.responderPort = m_tcpServerPort;

        const BitTorrent::STUN::Message request(BitTorrent::STUN::MessageClass::Request, BitTorrent::STUN::Method::Binding, m_tcpPending.id);
        m_tcpSocket->write(request.serialize());
        m_tcpProbeTimer.start(TCP_PROBE_TIMEOUT_MS);
    }

    void STUNManager::onTcpReadyRead()
    {
        if (!m_tcpSocket)
            return;

        m_tcpBuffer.append(m_tcpSocket->readAll());

        while (true)
        {
            const int frameSize = stunFrameSize(m_tcpBuffer);
            if (frameSize < 0)
                return;  // header still incomplete

            if (frameSize > MAX_TCP_FRAME_BYTES)
            {
                emit logMessage(QStringLiteral("STUN：TCP 保活通道收到异常帧，重建连接。"), true);
                closeTcpProbe();
                scheduleServerAdvance(Transport::Tcp);
                return;
            }

            if (m_tcpBuffer.size() < frameSize)
                return;

            const QByteArray frame = m_tcpBuffer.left(frameSize);
            m_tcpBuffer.remove(0, frameSize);

            BitTorrent::STUN::Message response;
            if (!BitTorrent::STUN::Message::parse(frame, response))
                continue;
            if (!m_tcpPending.active)
                continue;
            if (!response.isSuccessResponse())
                continue;
            if (response.transactionID() != m_tcpPending.id)
                continue;
            if (!response.hasMappedAddress())
                continue;

            m_tcpPending.active = false;
            m_tcpProbeTimer.stop();
            m_tcpServerAnswered = true;
            reportProbeSuccess(Transport::Tcp, response.mappedAddress(), response.mappedPort());
            return;
        }
    }

    void STUNManager::onTcpSocketError()
    {
        if (!m_tcpSocket)
            return;

        const QString reason = m_tcpSocket->errorString();
        closeTcpProbe();
        m_tcpProbeTimer.stop();
        reportProbeFailure(Transport::Tcp, QStringLiteral("连接失败：%1").arg(reason));
    }

    void STUNManager::onTcpProbeTimeout()
    {
        if (!m_tcpSocket)
            return;

        if (m_tcpSocket->state() != QAbstractSocket::ConnectedState)
        {
            closeTcpProbe();
            reportProbeFailure(Transport::Tcp, QStringLiteral("连接超时"));
            return;
        }

        if (!m_tcpPending.active)
            return;

        // The stream is up but the peer never answered the Binding Request, so it most
        // likely does not speak STUN over TCP. The connection still holds the TCP
        // binding on the carrier NAT and is therefore kept open.
        m_tcpPending.active = false;

        if (!m_tcpServerAnswered && !m_tcpUnsupportedWarned)
        {
            m_tcpUnsupportedWarned = true;
            emit logMessage(QStringLiteral("STUN：服务器 [%1:%2] 未响应 TCP 上的 Binding 请求，"
                                           "无法读取 TCP 公网端口（TCP 映射仍在维持）。")
                                .arg(m_tcpServerAddress.toString())
                                .arg(m_tcpServerPort), true);
        }
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

    void STUNManager::reportProbeFailure(Transport transport, const QString &reason)
    {
        int &failures = (transport == Transport::Udp) ? m_udpFailures : m_tcpFailures;
        ++failures;

        emit logMessage(QStringLiteral("STUN：%1 保活失败（%2），连续 %3 次。")
                            .arg(transportName(transport), reason)
                            .arg(failures), true);

        if (failures >= MAX_PROBE_FAILURES)
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
            if ((m_currentServerIndex < 0) || (m_currentServerIndex >= m_servers.size()))
                m_currentServerIndex = 0;

            ServerEndpoint &endpoint = m_servers[m_currentServerIndex];
            if (!resolveEndpointSync(endpoint))
            {
                m_currentServerIndex = (m_currentServerIndex + 1) % m_servers.size();
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
            m_currentServerIndex = (m_currentServerIndex + 1) % m_servers.size();
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
