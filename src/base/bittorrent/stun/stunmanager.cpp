#include "stunmanager.h"

#include <QDateTime>
#include <QNetworkDatagram>
#include <QThreadPool>

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
        connect(&m_keepAliveTimer, &QTimer::timeout, this, &STUNManager::onKeepAliveTimeout);

        parseServerList();
    }

    STUNManager::~STUNManager()
    {
        stop();
    }

    bool STUNManager::isEnabled() const
    {
        return m_enabled;
    }

    void STUNManager::setEnabled(bool enabled)
    {
        if (m_enabled == enabled)
            return;

        m_enabled = enabled;
        if (m_enabled)
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
        m_keepAliveIntervalSec = qBound(10, seconds, 300);
        if (m_keepAliveTimer.isActive())
            m_keepAliveTimer.setInterval(m_keepAliveIntervalSec * 1000);
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

    void STUNManager::setStatus(STUNStatus newStatus)
    {
        if (m_status == newStatus)
            return;

        m_status = newStatus;
        emit statusChanged(m_status);
    }

    void STUNManager::parseServerList()
    {
        m_servers.clear();
        for (const QString &item : m_serverStrings)
        {
            const QString trimmed = item.trimmed();
            if (trimmed.isEmpty())
                continue;

            ServerEndpoint ep;
            const int colonIdx = trimmed.lastIndexOf(u':');
            if (colonIdx != -1)
            {
                ep.host = trimmed.left(colonIdx).trimmed();
                bool ok = false;
                const int p = trimmed.mid(colonIdx + 1).toInt(&ok);
                ep.port = (ok && p > 0 && p <= 65535) ? static_cast<quint16>(p) : 3478;
            }
            else
            {
                ep.host = trimmed;
                ep.port = 3478;
            }

            QHostAddress directIp(ep.host);
            if (!directIp.isNull())
            {
                ep.resolvedAddress = directIp;
                ep.isResolved = true;
            }

            m_servers.append(ep);
        }

        m_currentServerIndex = 0;
    }

    void STUNManager::start()
    {
        if (m_servers.isEmpty())
            parseServerList();

        if (m_localPort == 0)
        {
            setStatus(STUNStatus::Error);
            emit logMessage(QStringLiteral("STUN: 本地监听端口尚未设置，等待 Session 初始化..."), true);
            return;
        }

        m_enabled = true;

        // Initialize background socket on port 0 for ongoing WAN IP monitoring and keepalive probes
        m_socket = std::make_unique<QUdpSocket>(this);
        connect(m_socket.get(), &QUdpSocket::readyRead, this, &STUNManager::onSocketReadyRead);
        m_socket->bind(QHostAddress::AnyIPv4, 0);

        emit logMessage(QStringLiteral("STUN: 服务已启动 (本地监听端口 %1)...").arg(m_localPort));
        resolveNextServer();

        m_keepAliveTimer.start(m_keepAliveIntervalSec * 1000);
    }

    bool STUNManager::discoverMappedPortSync(int timeoutMs)
    {
        if (m_servers.isEmpty())
            parseServerList();

        if (m_localPort == 0)
            return false;

        // Ensure current server has resolved IP
        ServerEndpoint &ep = m_servers[m_currentServerIndex];
        if (!ep.isResolved)
        {
            const QHostInfo info = QHostInfo::fromName(ep.host);
            if (info.error() == QHostInfo::NoError && !info.addresses().isEmpty())
            {
                for (const QHostAddress &addr : info.addresses())
                {
                    if (addr.protocol() == QAbstractSocket::IPv4Protocol)
                    {
                        ep.resolvedAddress = addr;
                        ep.isResolved = true;
                        break;
                    }
                }
                if (!ep.isResolved)
                {
                    ep.resolvedAddress = info.addresses().first();
                    ep.isResolved = true;
                }
            }
        }

        if (!ep.isResolved)
        {
            emit logMessage(QStringLiteral("STUN: 无法解析 STUN 服务器 [%1]").arg(ep.host), true);
            return false;
        }

        QUdpSocket probeSocket;
        if (!probeSocket.bind(QHostAddress::AnyIPv4, m_localPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
        {
            emit logMessage(QStringLiteral("STUN: 无法绑定本地端口 %1 执行映射探测").arg(m_localPort), true);
            return false;
        }

        const STUN::TransactionID transId = STUN::TransactionID::generate();
        const STUN::Message req(STUN::MessageClass::Request, STUN::Method::Binding, transId);
        const QByteArray payload = req.serialize();

        probeSocket.writeDatagram(payload, ep.resolvedAddress, ep.port);

        if (!probeSocket.waitForReadyRead(timeoutMs))
        {
            emit logMessage(QStringLiteral("STUN: 探测服务器 [%1] 响应超时").arg(ep.host), true);
            probeSocket.close();
            return false;
        }

        while (probeSocket.hasPendingDatagrams())
        {
            QNetworkDatagram datagram = probeSocket.receiveDatagram();
            STUN::Message resp;
            if (STUN::Message::parse(datagram.data(), resp) && resp.isSuccessResponse() && resp.hasMappedAddress())
            {
                m_mappedAddress = resp.mappedAddress();
                m_mappedPort = resp.mappedPort();
                setStatus(STUNStatus::Mapped);

                emit logMessage(QStringLiteral("STUN: 成功探测并建立公网映射 %1:%2 (本地端口: %3)")
                                    .arg(m_mappedAddress.toString())
                                    .arg(m_mappedPort)
                                    .arg(m_localPort));
                emit mappedEndpointChanged(m_mappedAddress, m_mappedPort);
                probeSocket.close();
                return true;
            }
        }

        probeSocket.close();
        return false;
    }

    void STUNManager::stop()
    {
        m_enabled = false;
        m_keepAliveTimer.stop();
        m_hasPendingProbe = false;

        if (m_socket)
        {
            m_socket->close();
            m_socket.reset();
        }

        setStatus(STUNStatus::Disabled);
    }

    void STUNManager::restart()
    {
        stop();
        start();
    }

    void STUNManager::resolveNextServer()
    {
        if (m_servers.isEmpty())
        {
            setStatus(STUNStatus::Error);
            return;
        }

        if (m_currentServerIndex >= m_servers.size())
            m_currentServerIndex = 0;

        ServerEndpoint &ep = m_servers[m_currentServerIndex];
        if (ep.isResolved)
        {
            setStatus(STUNStatus::Probing);
            sendBindingRequest(ep.resolvedAddress, ep.port);
            return;
        }

        setStatus(STUNStatus::Resolving);
        QHostInfo::lookupHost(ep.host, this, &STUNManager::onDnsResolved);
    }

    void STUNManager::onDnsResolved(const QHostInfo &hostInfo)
    {
        if (m_servers.isEmpty())
            return;

        ServerEndpoint &ep = m_servers[m_currentServerIndex];
        if (hostInfo.hostName() != ep.host)
            return;

        if (hostInfo.error() != QHostInfo::NoError || hostInfo.addresses().isEmpty())
        {
            emit logMessage(QStringLiteral("STUN: 解析服务器 [%1] 失败: %2，正在切换备用服务器...")
                                .arg(ep.host, hostInfo.errorString()), true);
            switchNextServer();
            return;
        }

        // Pick first IPv4 address
        for (const QHostAddress &addr : hostInfo.addresses())
        {
            if (addr.protocol() == QAbstractSocket::IPv4Protocol)
            {
                ep.resolvedAddress = addr;
                ep.isResolved = true;
                break;
            }
        }

        if (!ep.isResolved)
        {
            ep.resolvedAddress = hostInfo.addresses().first();
            ep.isResolved = true;
        }

        setStatus(STUNStatus::Probing);
        sendBindingRequest(ep.resolvedAddress, ep.port);
    }

    void STUNManager::switchNextServer()
    {
        m_probeFailures = 0;
        m_hasPendingProbe = false;
        m_currentServerIndex = (m_currentServerIndex + 1) % m_servers.size();
        resolveNextServer();
    }

    void STUNManager::sendBindingRequest(const QHostAddress &addr, quint16 port, bool changeIP, bool changePort)
    {
        if (!m_socket || !m_socket->isOpen())
            return;

        const STUN::TransactionID transId = STUN::TransactionID::generate();
        m_currentTransactionId = transId;
        m_hasPendingProbe = true;

        STUN::Message req(STUN::MessageClass::Request, STUN::Method::Binding, transId);
        if (changeIP || changePort)
            req.setChangeRequest(changeIP, changePort);

        const QByteArray payload = req.serialize();
        m_socket->writeDatagram(payload, addr, port);
    }

    void STUNManager::onKeepAliveTimeout()
    {
        if (!m_enabled || m_servers.isEmpty())
            return;

        if (m_hasPendingProbe)
        {
            m_probeFailures++;
            if (m_probeFailures >= 3)
            {
                emit logMessage(QStringLiteral("STUN: 当前服务器响应超时，正在自动切换备用服务器..."), true);
                switchNextServer();
                return;
            }
        }

        const ServerEndpoint &ep = m_servers[m_currentServerIndex];
        if (ep.isResolved)
        {
            sendBindingRequest(ep.resolvedAddress, ep.port);
        }
        else
        {
            resolveNextServer();
        }
    }

    void STUNManager::onSocketReadyRead()
    {
        while (m_socket && m_socket->hasPendingDatagrams())
        {
            QNetworkDatagram datagram = m_socket->receiveDatagram();
            const QByteArray data = datagram.data();
            const QHostAddress sender = datagram.senderAddress();
            const quint16 senderPort = static_cast<quint16>(datagram.senderPort());

            STUN::Message resp;
            if (!STUN::Message::parse(data, resp))
                continue;

            if (resp.isSuccessResponse())
            {
                handleStunResponse(resp, sender, senderPort);
            }
        }
    }

    void STUNManager::handleStunResponse(const STUN::Message &msg, const QHostAddress &sender, quint16 senderPort)
    {
        Q_UNUSED(sender);
        Q_UNUSED(senderPort);

        m_hasPendingProbe = false;
        m_probeFailures = 0;

        if (!msg.hasMappedAddress())
            return;

        const QHostAddress newMappedAddr = msg.mappedAddress();
        setStatus(STUNStatus::Mapped);

        const bool changed = (m_mappedAddress != newMappedAddr);
        if (changed)
        {
            m_mappedAddress = newMappedAddr;
            emit logMessage(QStringLiteral("STUN: 检测到公网 IP 变更为: %1").arg(m_mappedAddress.toString()));
            emit mappedEndpointChanged(m_mappedAddress, m_mappedPort);
        }
    }

    void STUNManager::runNATTypeTest()
    {
        if (m_servers.isEmpty())
            parseServerList();

        emit logMessage(QStringLiteral("STUN: 正在发起网络 NAT 类型深度诊断 (RFC 5780)..."));

        const QStringList servers = m_serverStrings;

        QThreadPool::globalInstance()->start([this, servers]()
        {
            QStringList candidateServers = servers;
            for (const QString &preferred : {QStringLiteral("stun.miwifi.com:3478"), QStringLiteral("stun.douyucdn.cn:18000")})
            {
                candidateServers.removeAll(preferred);
                candidateServers.prepend(preferred);
            }

            NATType detectedType = NATType::Unknown;
            QString detectedDetails;

            for (const QString &serverStr : candidateServers)
            {
                const QString trimmed = serverStr.trimmed();
                if (trimmed.isEmpty())
                    continue;

                QString host = trimmed;
                quint16 port = 3478;
                const int colonIdx = trimmed.lastIndexOf(u':');
                if (colonIdx != -1)
                {
                    host = trimmed.left(colonIdx).trimmed();
                    bool ok = false;
                    const int p = trimmed.mid(colonIdx + 1).toInt(&ok);
                    if (ok && p > 0 && p <= 65535)
                        port = static_cast<quint16>(p);
                }

                QHostAddress targetAddr(host);
                if (targetAddr.isNull())
                {
                    const QHostInfo hostInfo = QHostInfo::fromName(host);
                    if (hostInfo.error() != QHostInfo::NoError || hostInfo.addresses().isEmpty())
                        continue;

                    for (const QHostAddress &addr : hostInfo.addresses())
                    {
                        if (addr.protocol() == QAbstractSocket::IPv4Protocol)
                        {
                            targetAddr = addr;
                            break;
                        }
                    }
                    if (targetAddr.isNull())
                        targetAddr = hostInfo.addresses().first();
                }

                QUdpSocket diagSocket;
                if (!diagSocket.bind(QHostAddress::AnyIPv4, 0))
                    continue;

                // Step 1: Test 1 - Primary Binding Request
                const STUN::TransactionID tid1 = STUN::TransactionID::generate();
                const STUN::Message req1(STUN::MessageClass::Request, STUN::Method::Binding, tid1);
                diagSocket.writeDatagram(req1.serialize(), targetAddr, port);

                if (!diagSocket.waitForReadyRead(1500))
                    continue;

                QNetworkDatagram datagram1 = diagSocket.receiveDatagram();
                STUN::Message resp1;
                if (!STUN::Message::parse(datagram1.data(), resp1) || !resp1.isSuccessResponse() || !resp1.hasMappedAddress())
                    continue;

                const QHostAddress mappedAddr1 = resp1.mappedAddress();
                const quint16 mappedPort1 = resp1.mappedPort();

                // If server provided OTHER-ADDRESS (RFC 5780 / RFC 3489 full capability)
                if (resp1.hasOtherAddress() && !resp1.otherAddress().isNull())
                {
                    const QHostAddress otherIP = resp1.otherAddress();
                    const quint16 otherPort = (resp1.otherPort() > 0) ? resp1.otherPort() : port;

                    // Step 2: Test 2 - Send to Other IP/Port to test Mapping (EIM vs Symmetric)
                    const STUN::TransactionID tid2 = STUN::TransactionID::generate();
                    const STUN::Message req2(STUN::MessageClass::Request, STUN::Method::Binding, tid2);
                    diagSocket.writeDatagram(req2.serialize(), otherIP, otherPort);

                    if (diagSocket.waitForReadyRead(1500))
                    {
                        QNetworkDatagram datagram2 = diagSocket.receiveDatagram();
                        STUN::Message resp2;
                        if (STUN::Message::parse(datagram2.data(), resp2) && resp2.hasMappedAddress())
                        {
                            if (resp2.mappedPort() != mappedPort1 || resp2.mappedAddress() != mappedAddr1)
                            {
                                detectedType = NATType::Symmetric;
                                detectedDetails = QStringLiteral("不同外网目标映射的端口不一致 (Symmetric NAT)，无法支持外部直接连入");
                                break;
                            }
                        }
                    }

                    // Step 3: Test 3 - Send to Primary with CHANGE-REQUEST (change IP + change Port)
                    const STUN::TransactionID tid3 = STUN::TransactionID::generate();
                    STUN::Message req3(STUN::MessageClass::Request, STUN::Method::Binding, tid3);
                    req3.setChangeRequest(true, true);
                    diagSocket.writeDatagram(req3.serialize(), targetAddr, port);

                    if (diagSocket.waitForReadyRead(1500))
                    {
                        QNetworkDatagram datagram3 = diagSocket.receiveDatagram();
                        STUN::Message resp3;
                        if (STUN::Message::parse(datagram3.data(), resp3) && resp3.isSuccessResponse())
                        {
                            detectedType = NATType::FullCone;
                            detectedDetails = QStringLiteral("全锥形 NAT (NAT1 / Full Cone)！支持外部任意 Peer 直接建立入站连接");
                            break;
                        }
                    }

                    // Step 4: Test 4 - Send to Primary with CHANGE-REQUEST (change Port only)
                    const STUN::TransactionID tid4 = STUN::TransactionID::generate();
                    STUN::Message req4(STUN::MessageClass::Request, STUN::Method::Binding, tid4);
                    req4.setChangeRequest(false, true);
                    diagSocket.writeDatagram(req4.serialize(), targetAddr, port);

                    if (diagSocket.waitForReadyRead(1500))
                    {
                        QNetworkDatagram datagram4 = diagSocket.receiveDatagram();
                        STUN::Message resp4;
                        if (STUN::Message::parse(datagram4.data(), resp4) && resp4.isSuccessResponse())
                        {
                            detectedType = NATType::RestrictedCone;
                            detectedDetails = QStringLiteral("受限锥形 NAT (NAT2 / Restricted Cone)，外部 Peer 连入受限");
                            break;
                        }
                    }

                    // Neither change-request received -> Port Restricted Cone
                    detectedType = NATType::PortRestrictedCone;
                    detectedDetails = QStringLiteral("端口受限锥形 NAT (NAT3 / Port Restricted Cone)，仅可连向已知端口");
                    break;
                }
                else
                {
                    // Basic STUN server without OTHER-ADDRESS
                    detectedType = NATType::FullCone;
                    detectedDetails = QStringLiteral("STUN 服务器成功映射，网络表现为 Full Cone (全锥形)");
                    break;
                }
            }

            if (detectedType == NATType::Unknown)
            {
                detectedType = NATType::UdpBlocked;
                detectedDetails = QStringLiteral("无法连接 STUN 服务器，UDP 可能被运营商或防火墙阻断");
            }

            QMetaObject::invokeMethod(this, [this, detectedType, detectedDetails]()
            {
                finalizeDiagnostic(detectedType, detectedDetails);
            }, Qt::QueuedConnection);
        });
    }

    void STUNManager::finalizeDiagnostic(NATType type, const QString &details)
    {
        m_natType = type;
        emit logMessage(QStringLiteral("STUN: NAT 诊断完成 -> %1: %2").arg(natTypeToString(type), details));
        emit natTypeDetected(type, details);
    }
}
