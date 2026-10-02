#include "stuntcpchannel.h"

#include <QtEndian>

namespace
{
    // A STUN message larger than this over TCP means the framing was lost; drop the
    // connection rather than accumulating an unbounded buffer.
    constexpr int MAX_TCP_FRAME_BYTES = 4096;

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
}

namespace BitTorrent
{
    STUNTcpChannel::STUNTcpChannel(QObject *parent)
        : QObject(parent)
    {
        connect(&m_probeTimer, &QTimer::timeout, this, &STUNTcpChannel::onProbeTimeout);
        m_probeTimer.setSingleShot(true);
    }

    void STUNTcpChannel::setLocalPort(quint16 port)
    {
        m_localPort = port;
    }

    bool STUNTcpChannel::isRunning() const
    {
        return m_running;
    }

    void STUNTcpChannel::start(const QHostAddress &serverAddress, quint16 serverPort)
    {
        if (m_localPort == 0)
            return;

        const bool sameServer = m_running
            && (m_serverAddress == serverAddress) && (m_serverPort == serverPort);

        m_serverAddress = serverAddress;
        m_serverPort = serverPort;
        m_running = true;

        // A closure is already being handled on the next event-loop turn; starting
        // another connection here would race it.
        if (m_deferred)
            return;

        if (sameServer && m_socket && (m_socket->state() == QAbstractSocket::ConnectedState))
        {
            sendBindingRequest();
            return;
        }

        // A connect to the same server is already underway; let it finish.
        if (sameServer && m_socket && (m_socket->state() == QAbstractSocket::ConnectingState))
            return;

        connectToServer();
    }

    void STUNTcpChannel::stop()
    {
        m_running = false;
        m_deferred = false;
        m_retryPending = false;
        m_probeTimer.stop();
        closeSocket();
    }

    void STUNTcpChannel::connectToServer()
    {
        // A carrier NAT ties the TCP binding to the source port of the SYN, so every
        // attempt has to leave from the listening port again. The socket is rebuilt
        // instead of reused, because abort() also drops the bind.
        //
        // The previous socket is destroyed, not merely aborted, before the new one
        // binds. abort() leaves it holding the local port, so the next bind would fail
        // and the channel would walk away from a server that is actually fine.
        // libtorrent's listener is unaffected: it is a different socket, and
        // ShareAddress allows both.
        closeSocket();

        m_socket = std::make_unique<QTcpSocket>();
        connect(m_socket.get(), &QTcpSocket::connected, this, &STUNTcpChannel::onConnected);
        connect(m_socket.get(), &QTcpSocket::readyRead, this, &STUNTcpChannel::onReadyRead);
        connect(m_socket.get(), &QTcpSocket::errorOccurred, this, &STUNTcpChannel::onSocketError);

        // ShareAddress keeps this socket from displacing libtorrent's listener on the
        // same port. It only ever exists for the duration of one connection.
        if (!m_socket->bind(QHostAddress::AnyIPv4, m_localPort,
                            QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint))
        {
            const QString reason = m_socket->errorString();
            m_socket.reset();

            // The port can stay unavailable for a moment right after the previous
            // connection was torn down. Retry briefly before concluding it is genuinely
            // taken; an unbounded retry would spin forever on a port that is held.
            if (m_bindAttempts < MAX_BIND_ATTEMPTS)
            {
                connectToServerDeferred();
                return;
            }

            m_bindAttempts = 0;
            m_running = false;
            emit connectFailed(QStringLiteral("无法在本地端口 %1 上绑定 TCP 保活套接字（%2）").arg(m_localPort).arg(reason));
            return;
        }

        m_bindAttempts = 0;

        m_buffer.clear();
        m_requestPending = false;
        m_serverAnswered = false;

        m_socket->connectToHost(m_serverAddress, m_serverPort);
        m_probeTimer.start(PROBE_TIMEOUT_MS);
    }

    void STUNTcpChannel::connectToServerDeferred()
    {
        if (m_retryPending)
            return;

        m_retryPending = true;
        ++m_bindAttempts;
        QTimer::singleShot(250, this, [this]()
        {
            m_retryPending = false;
            if (m_running)
                connectToServer();
        });
    }

    void STUNTcpChannel::closeSocket()
    {
        m_requestPending = false;
        m_buffer.clear();

        if (m_socket)
        {
            m_socket->disconnect(this);
            m_socket->abort();
            m_socket.reset();
        }
    }

    void STUNTcpChannel::sendBindingRequest()
    {
        if (!m_socket || (m_socket->state() != QAbstractSocket::ConnectedState))
            return;

        m_requestPending = true;
        m_transactionId = STUN::TransactionID::generate();

        const STUN::Message request(STUN::MessageClass::Request, STUN::Method::Binding, m_transactionId);
        m_socket->write(request.serialize());
        m_probeTimer.start(PROBE_TIMEOUT_MS);
    }

    void STUNTcpChannel::onConnected()
    {
        m_buffer.clear();
        m_serverAnswered = false;
        sendBindingRequest();
    }

    void STUNTcpChannel::onReadyRead()
    {
        if (!m_socket)
            return;

        m_buffer.append(m_socket->readAll());

        while (true)
        {
            const int frameSize = stunFrameSize(m_buffer);
            if (frameSize < 0)
                return;  // header still incomplete

            if (frameSize > MAX_TCP_FRAME_BYTES)
            {
                // Framing is lost, so this stream can no longer be trusted. Reconnecting
                // to the same server is enough: the failure is in the stream, not in the
                // server's willingness to answer. Deferred, because this runs inside the
                // socket's own readyRead handler.
                if (!m_deferred)
                {
                    m_deferred = true;
                    QTimer::singleShot(0, this, [this]()
                    {
                        m_deferred = false;
                        if (m_running)
                            connectToServer();
                    });
                }
                return;
            }

            if (m_buffer.size() < frameSize)
                return;

            const QByteArray frame = m_buffer.left(frameSize);
            m_buffer.remove(0, frameSize);

            STUN::Message response;
            if (!STUN::Message::parse(frame, response))
                continue;
            if (!m_requestPending)
                continue;
            if (!response.isSuccessResponse())
                continue;
            if (response.transactionID() != m_transactionId)
                continue;
            if (!response.hasMappedAddress())
                continue;

            m_requestPending = false;
            m_probeTimer.stop();
            m_serverAnswered = true;
            m_unanswered = 0;
            emit mapped(response.mappedAddress(), response.mappedPort());
            return;
        }
    }

    void STUNTcpChannel::onSocketError(const QAbstractSocket::SocketError error)
    {
        if (!m_running || !m_socket)
            return;

        const QString reason = m_socket->errorString();
        const bool answered = m_serverAnswered;
        const bool refused = (error == QAbstractSocket::ConnectionRefusedError);

        m_probeTimer.stop();
        // Detach first, so abort() cannot re-enter this handler. The socket itself is
        // destroyed later: this function runs inside its errorOccurred signal.
        m_socket->disconnect(this);
        m_socket->abort();

        if (m_deferred)
            return;

        m_deferred = true;
        QTimer::singleShot(0, this, [this, answered, refused, reason]()
        {
            m_deferred = false;
            if (!m_running)
                return;

            // The servers that speak STUN over TCP close the connection themselves after
            // a short idle time, even while it is still being used. Once a server has
            // answered once, that closure only means the binding has to be refreshed on a
            // new connection to the same server - it says nothing about the server being
            // down.
            if (answered && !refused)
            {
                connectToServer();
                return;
            }

            closeSocket();
            m_running = false;
            emit connectFailed(QStringLiteral("连接失败：%1").arg(reason));
        });
    }

    void STUNTcpChannel::onProbeTimeout()
    {
        if (!m_running || !m_socket)
            return;

        if (m_socket->state() != QAbstractSocket::ConnectedState)
        {
            closeSocket();
            m_running = false;
            emit connectFailed(QStringLiteral("连接超时"));
            return;
        }

        if (!m_requestPending || m_serverAnswered)
            return;

        m_requestPending = false;

        // The stream is up but the peer does not answer Binding Requests, so it cannot
        // report the public TCP port - the only reason to keep a TCP channel at all.
        // Counted per server: one silent reply can be a slow server, several in a row
        // means it will never answer.
        if (++m_unanswered >= MAX_PROBE_FAILURES)
        {
            m_unanswered = 0;
            closeSocket();
            m_running = false;
            emit bindingUnanswered();
        }
    }
}
