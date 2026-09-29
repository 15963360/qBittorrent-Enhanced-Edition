#pragma once

#include <chrono>
#include <QHostAddress>
#include <QHostInfo>
#include <QObject>
#include <QStringList>
#include <QTimer>
#include <QUdpSocket>

#include "stunmessage.h"

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

        STUNStatus status() const;
        NATType natType() const;

        QHostAddress mappedAddress() const;
        quint16 mappedPort() const;

        void start();
        void stop();
        void restart();

        // Trigger manual/diagnostic NAT type test (runs on dedicated ephemeral port, no collision)
        void runNATTypeTest();

        // Discover mapped port on localPort synchronously before libtorrent starts or re-binds
        bool discoverMappedPortSync(int timeoutMs = 1500);

    signals:
        void mappedEndpointChanged(const QHostAddress &ip, quint16 port);
        void statusChanged(BitTorrent::STUNStatus status);
        void natTypeDetected(BitTorrent::NATType type, const QString &details);
        void logMessage(const QString &msg, bool isWarning = false);

    private slots:
        void onSocketReadyRead();
        void onKeepAliveTimeout();
        void onDnsResolved(const QHostInfo &hostInfo);

    private:
        struct ServerEndpoint
        {
            QString host;
            quint16 port {3478};
            QHostAddress resolvedAddress;
            bool isResolved {false};
        };

        void parseServerList();
        void resolveNextServer();
        void sendBindingRequest(const QHostAddress &addr, quint16 port, bool changeIP = false, bool changePort = false);
        void handleStunResponse(const STUN::Message &msg, const QHostAddress &sender, quint16 senderPort);
        void switchNextServer();
        void setStatus(STUNStatus newStatus);
        void finalizeDiagnostic(NATType type, const QString &details);

        bool m_enabled {false};
        quint16 m_localPort {0};
        QStringList m_serverStrings;
        QList<ServerEndpoint> m_servers;
        int m_currentServerIndex {0};
        int m_keepAliveIntervalSec {DEFAULT_KEEPALIVE_INTERVAL_SEC};

        STUNStatus m_status {STUNStatus::Disabled};
        NATType m_natType {NATType::Unknown};

        QHostAddress m_mappedAddress;
        quint16 m_mappedPort {0};

        std::unique_ptr<QUdpSocket> m_socket;
        QTimer m_keepAliveTimer;

        // Pending transaction tracking
        STUN::TransactionID m_currentTransactionId {};
        bool m_hasPendingProbe {false};
        int m_probeFailures {0};
    };

    QString natTypeToString(NATType type);
    QString stunStatusToString(STUNStatus status);
}
