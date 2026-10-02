#pragma once

#include <memory>

#include <QByteArray>
#include <QHostAddress>
#include <QObject>
#include <QTcpSocket>
#include <QTimer>

#include "stunmessage.h"

namespace BitTorrent
{
    // The TCP half of the STUN keepalive. A carrier-grade NAT only keeps the TCP binding
    // while traffic keeps leaving the listening port, and public STUN servers close an
    // idle TCP connection after a short fixed time (measured at roughly 60 seconds, and
    // at 3 seconds for one of them). So this channel holds exactly one connection, sends
    // a Binding Request on it at the keepalive interval, and opens a fresh one to the
    // same server the moment the server closes it. The closure itself is not a failure:
    // only a server that cannot be reached, or that never answers a Binding Request, is
    // given up on.
    class STUNTcpChannel final : public QObject
    {
        Q_OBJECT
        Q_DISABLE_COPY_MOVE(STUNTcpChannel)

    public:
        static constexpr int PROBE_TIMEOUT_MS = 4000;
        static constexpr int MAX_PROBE_FAILURES = 3;

        explicit STUNTcpChannel(QObject *parent = nullptr);

        void setLocalPort(quint16 port);

        bool isRunning() const;

        // Opens a connection to this server from the listening port. A call while one is
        // already open to the same server just sends another Binding Request on it.
        void start(const QHostAddress &serverAddress, quint16 serverPort);

        void stop();

    signals:
        void mapped(const QHostAddress &ip, quint16 port);

        // The server could not be reached at all. The channel has already stopped.
        void connectFailed(const QString &reason);

        // The TCP connection came up, but no Binding response arrived before the probe
        // timed out. Reported once per connection; the channel keeps the connection so
        // the caller can decide whether to give the server another chance.
        void bindingUnanswered();

    private:
        void connectToServer();
        void connectToServerDeferred();
        void closeSocket();
        void sendBindingRequest();
        void onConnected();
        void onReadyRead();
        void onSocketError(QAbstractSocket::SocketError error);
        void onProbeTimeout();

        quint16 m_localPort {0};
        QHostAddress m_serverAddress;
        quint16 m_serverPort {0};
        bool m_running {false};

        std::unique_ptr<QTcpSocket> m_socket;
        QByteArray m_buffer;
        QTimer m_probeTimer;

        bool m_requestPending {false};
        STUN::TransactionID m_transactionId {};
        // Set once this connection has produced a Binding response, so a closure after
        // that point is treated as the server's idle timeout rather than a failure.
        bool m_serverAnswered {false};
        int m_unanswered {0};
        // A reconnect or a failure is handled on the next event-loop turn, never inside
        // the socket's own signal: destroying a QTcpSocket from within its handler is
        // unsafe. While this is set, start() leaves the channel alone.
        bool m_deferred {false};
        // Set while a short retry is already pending, so a bind that fails twice does
        // not schedule two of them.
        bool m_retryPending {false};
        int m_bindAttempts {0};
        static constexpr int MAX_BIND_ATTEMPTS = 5;
    };
}
