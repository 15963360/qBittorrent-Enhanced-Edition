#pragma once

#include <atomic>
#include <memory>

#include <QHostAddress>
#include <QHostInfo>
#include <QObject>
#include <QStringList>
#include <QThreadPool>
#include <QTimer>
#include <QUdpSocket>

#include "stunmessage.h"
#include "stuntcpchannel.h"

namespace BitTorrent
{
    enum class NATType
    {
        Unknown,
        OpenInternet,
        FullCone,            // NAT1
        RestrictedCone,      // NAT2
        PortRestrictedCone,  // NAT3
        Symmetric,           // NAT4
        UdpBlocked
    };

    enum class STUNStatus
    {
        Disabled,
        Resolving,
        Probing,
        Mapped,
        Error
    };

    class STUNManager : public QObject
    {
        Q_OBJECT
        Q_DISABLE_COPY_MOVE(STUNManager)

    public:
        static const QStringList DEFAULT_STUN_SERVERS;
        static constexpr int DEFAULT_KEEPALIVE_INTERVAL_SEC = 25;
        static constexpr int MIN_KEEPALIVE_INTERVAL_SEC = 10;
        static constexpr int MAX_KEEPALIVE_INTERVAL_SEC = 300;
        static constexpr int UDP_PROBE_TIMEOUT_MS = 900;
        static constexpr int MAX_PROBE_FAILURES = 3;
        static constexpr int NAT_TEST_TIMEOUT_MS = 1500;

        explicit STUNManager(QObject *parent = nullptr);
        ~STUNManager() override;

        bool isEnabled() const;
        void setEnabled(bool enabled);

        quint16 localPort() const;
        void setLocalPort(quint16 port);

        QStringList stunServers() const;
        void setStunServers(const QStringList &servers);

        int keepAliveInterval() const;
        void setKeepAliveInterval(int seconds);

        // Carrier-grade NAT allocates the UDP and the TCP binding independently, so a
        // STUN binding only refreshes the transport it was sent over. Each transport
        // therefore has its own keepalive channel and its own switch.
        bool isUdpKeepAliveEnabled() const;
        void setUdpKeepAliveEnabled(bool enabled);
        bool isTcpKeepAliveEnabled() const;
        void setTcpKeepAliveEnabled(bool enabled);

        STUNStatus status() const;
        NATType natType() const;

        // Endpoint announced to trackers and peers. Trackers carry a single port, so
        // only one of the two transports can ever be advertised; see
        // updateAnnouncedEndpoint() for which one wins.
        QHostAddress mappedAddress() const;
        quint16 mappedPort() const;

        QHostAddress udpMappedAddress() const;
        quint16 udpMappedPort() const;
        QHostAddress tcpMappedAddress() const;
        quint16 tcpMappedPort() const;
        bool hasUdpMapping() const;
        bool hasTcpMapping() const;

        void start();
        void stop();
        void restart();

        // RFC 5780 mapping/filtering probe. Self-contained: it never touches the
        // keepalive sockets and never drives the announced endpoint.
        void runNATTypeTest();
        bool isNATTestRunning() const;

        // Blocking probe on the listening port, used before libtorrent binds its
        // listeners so the very first announce carries the mapped port.
        bool discoverMappedPortSync(int timeoutMs = 1500);

    signals:
        void mappedEndpointChanged(const QHostAddress &ip, quint16 port);
        void statusChanged(BitTorrent::STUNStatus status);
        void natTypeDetected(BitTorrent::NATType type, const QString &details);
        void logMessage(const QString &msg, bool isWarning = false);

    private slots:
        void onKeepAliveTimeout();
        void onUdpProbeReadyRead();
        void onUdpProbeTimeout();
        void onTcpMapped(const QHostAddress &ip, quint16 port);
        void onTcpConnectFailed(const QString &reason);
        void onTcpBindingUnanswered();

    private:
        enum class Transport { Udp, Tcp };

        struct ServerEndpoint
        {
            QString host;
            quint16 port {3478};
            QHostAddress resolvedAddress;
            bool isResolved {false};
            // STUN over TCP is optional in RFC 5389 and most public servers do not
            // offer it. Once a server has proved it does not, the TCP channel skips
            // it instead of paying a fresh timeout on every rotation.
            bool tcpRefused {false};
        };

        struct PendingProbe
        {
            bool active {false};
            STUN::TransactionID id {};
            QHostAddress responderAddress;
            quint16 responderPort {0};
        };

        void parseServerList();
        bool resolveEndpointSync(ServerEndpoint &endpoint);
        int &serverIndex(Transport transport);
        ServerEndpoint *serverAt(int index);
        ServerEndpoint *currentServer(Transport transport);
        int nextServerIndex(Transport transport, int from) const;
        void ensureResolved(Transport transport);
        void onDnsResolved(Transport transport, const QString &host, const QHostInfo &hostInfo);
        void startProbe(Transport transport);
        void advanceServer(Transport transport);
        void scheduleServerAdvance(Transport transport);
        void refreshStatus();
        void setStatus(STUNStatus newStatus);
        void updateAnnouncedEndpoint();

        void startUdpProbe();
        void closeUdpProbe();
        void finishUdpProbe(bool success, const QHostAddress &ip = QHostAddress(), quint16 port = 0);

        void abortProbes();
        void stopInternal(bool disabledByUser);

        bool bindToLocalPort(QAbstractSocket &socket) const;
        void reportProbeSuccess(Transport transport, const QHostAddress &ip, quint16 port);
        void reportProbeFailure(Transport transport, const QString &reason, bool rotateImmediately = false);
        bool isTransportEnabled(Transport transport) const;
        QString transportName(Transport transport) const;

        bool m_enabled {false};
        quint16 m_localPort {0};
        QStringList m_serverStrings;
        QList<ServerEndpoint> m_servers;
        // Each transport walks the list on its own: the Chinese servers answer on UDP
        // only, so a shared index would drag the UDP channel off a working server
        // every time the TCP channel rotated past them.
        int m_udpServerIndex {0};
        int m_tcpServerIndex {0};
        int m_keepAliveIntervalSec {DEFAULT_KEEPALIVE_INTERVAL_SEC};

        bool m_udpKeepAliveEnabled {true};
        bool m_tcpKeepAliveEnabled {true};

        STUNStatus m_status {STUNStatus::Disabled};
        NATType m_natType {NATType::Unknown};

        // Last known public mapping per transport. These are facts about the carrier,
        // independent of whether this build keeps them alive, so turning a keepalive
        // off does not erase them.
        QHostAddress m_udpMappedAddress;
        quint16 m_udpMappedPort {0};
        QHostAddress m_tcpMappedAddress;
        quint16 m_tcpMappedPort {0};

        QHostAddress m_mappedAddress;  // announced endpoint
        quint16 m_mappedPort {0};

        // UDP channel: one short-lived socket per probe, bound to the listening port
        // so the carrier mapping being refreshed is the one peers actually use.
        std::unique_ptr<QUdpSocket> m_udpProbe;
        PendingProbe m_udpPending;
        QTimer m_udpProbeTimer;
        int m_udpFailures {0};
        // How many servers the UDP channel has already walked while trying to learn the
        // public port. Bounded, so a machine that cannot receive the replies settles on
        // one server instead of rotating forever.
        int m_udpRotations {0};
        bool m_udpUnconfirmedLogged {false};

        // TCP channel: one connection from the listening port, rebuilt whenever the
        // server closes it. See STUNTcpChannel for why a closure is not a failure.
        STUNTcpChannel m_tcpChannel;
        int m_tcpFailures {0};

        QTimer m_keepAliveTimer;

        // RFC 5780 diagnostics run on a private pool so they cannot occupy the global
        // pool, and their lifetime is bounded by this object.
        QThreadPool m_natTestPool;
        std::shared_ptr<std::atomic_bool> m_natTestCancel;
        bool m_natTestRunning {false};
    };

    QString natTypeToString(NATType type);
    QString stunStatusToString(STUNStatus status);
}
