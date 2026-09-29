/*
 * Bittorrent Client using Qt and libtorrent.
 * Copyright (C) 2026  qBittorrent Enhanced Edition contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give permission to
 * link this program with the OpenSSL project's "OpenSSL" library (or with
 * modified versions of it that use the same license as the "OpenSSL" library),
 * and distribute the linked executables. You must obey the GNU General Public
 * License in all respects for all of the code used other than "OpenSSL".  If you
 * modify file(s), you may extend this exception to your version of the file(s),
 * but you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 */

#include "stunportmapper.h"

#include <QtSystemDetection>

#ifdef Q_OS_UNIX
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>

#include <QDir>
#include <QNetworkDatagram>
#include <QSocketNotifier>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>

#include "base/global.h"

using namespace std::chrono_literals;

namespace
{
    constexpr std::chrono::milliseconds TCP_CONNECT_TIMEOUT = 5s;
    constexpr std::chrono::milliseconds TCP_RESPONSE_TIMEOUT = 10s;
    constexpr std::chrono::milliseconds UDP_RETRANSMIT_INTERVAL = 1s;
    constexpr int UDP_MAX_ATTEMPTS = 3;
    constexpr std::chrono::milliseconds RETRY_DELAY = 1s;
    constexpr std::chrono::milliseconds RECONNECT_DELAY = 5s;

#if defined(Q_OS_UNIX) && defined(SO_REUSEPORT)
#define QBT_STUN_PORT_SHARING_SUPPORTED
#endif

#ifdef QBT_STUN_PORT_SHARING_SUPPORTED
    using Protocol = Net::StunPortMapper::Protocol;

    QList<int> listOpenFileDescriptors()
    {
        QList<int> fds;
#ifdef Q_OS_LINUX
        const QStringList entries = QDir(u"/proc/self/fd"_s).entryList(QDir::Files | QDir::System | QDir::NoDotAndDotDot);
        if (!entries.isEmpty())
        {
            for (const QString &entry : entries)
            {
                bool ok = false;
                const int fd = entry.toInt(&ok);
                if (ok)
                    fds.append(fd);
            }
            return fds;
        }
#endif
        rlimit limit {};
        const int maxFD = ((::getrlimit(RLIMIT_NOFILE, &limit) == 0) && (limit.rlim_cur != RLIM_INFINITY))
            ? static_cast<int>(std::min<rlim_t>(limit.rlim_cur, 65536)) : 4096;
        for (int fd = 0; fd < maxFD; ++fd)
            fds.append(fd);
        return fds;
    }

    quint16 socketLocalPort(const int fd)
    {
        sockaddr_storage addr {};
        socklen_t addrLen = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &addrLen) != 0)
            return 0;

        if (addr.ss_family == AF_INET)
            return ntohs(reinterpret_cast<const sockaddr_in *>(&addr)->sin_port);
        if (addr.ss_family == AF_INET6)
            return ntohs(reinterpret_cast<const sockaddr_in6 *>(&addr)->sin6_port);
        return 0;
    }

    // libtorrent binds its TCP listen sockets with SO_REUSEADDR only and its
    // UDP sockets without any reuse option. Enable sharing on the sockets of
    // this process that are bound to `port`, so that the STUN socket can be
    // bound to the same port (the kernel checks the options of *all* sockets
    // bound to the port at bind() time).
    int enableAddressSharing(const Protocol protocol, const quint16 port)
    {
        const int wantedType = (protocol == Protocol::TCP) ? SOCK_STREAM : SOCK_DGRAM;
        const int enable = 1;
        int count = 0;

        for (const int fd : asConst(listOpenFileDescriptors()))
        {
            int type = 0;
            socklen_t len = sizeof(type);
            if ((::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0) || (type != wantedType))
                continue;
            if (socketLocalPort(fd) != port)
                continue;

            if (protocol == Protocol::TCP)
            {
                // only touch listening sockets, not established peer connections
                int isListening = 0;
                len = sizeof(isListening);
                if ((::getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &isListening, &len) != 0) || !isListening)
                    continue;
                ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) == 0)
                    ++count;
            }
            else
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == 0)
                    ++count;
            }
        }

        return count;
    }

    int createSharedSocket(const Protocol protocol, const quint16 port, QString &error)
    {
        const int fd = ::socket(AF_INET, ((protocol == Protocol::TCP) ? SOCK_STREAM : SOCK_DGRAM), 0);
        if (fd < 0)
        {
            error = QString::fromLocal8Bit(std::strerror(errno));
            return -1;
        }

        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        ::fcntl(fd, F_SETFL, (::fcntl(fd, F_GETFL, 0) | O_NONBLOCK));

        const int enable = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        // For UDP SO_REUSEPORT is intentionally not used: it would create a
        // load-balancing group with semantics we don't want.
        if (protocol == Protocol::TCP)
            ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));

        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        int result = ::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
        if ((result != 0) && (errno == EADDRINUSE) && (enableAddressSharing(protocol, port) > 0))
            result = ::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));

        if (result != 0)
        {
            error = QString::fromLocal8Bit(std::strerror(errno));
            ::close(fd);
            return -1;
        }

        return fd;
    }

    // Returns 0 on immediate success, EINPROGRESS if pending, or errno
    int connectSocket(const int fd, const Net::Stun::Endpoint &endpoint)
    {
        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(endpoint.address.toIPv4Address());
        addr.sin_port = htons(endpoint.port);

        if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0)
            return 0;
        return errno;
    }
#endif
}

Net::StunPortMapper::StunPortMapper(const Protocol protocol, QObject *parent)
    : QObject(parent)
    , m_protocol {protocol}
    , m_transactionTimer {new QTimer(this)}
    , m_keepAliveTimer {new QTimer(this)}
    , m_reconnectTimer {new QTimer(this)}
{
    m_transactionTimer->setSingleShot(true);
    m_keepAliveTimer->setSingleShot(true);
    m_reconnectTimer->setSingleShot(true);
    connect(m_transactionTimer, &QTimer::timeout, this, &StunPortMapper::onTransactionTimeout);
    connect(m_keepAliveTimer, &QTimer::timeout, this, &StunPortMapper::sendBindingRequest);
    connect(m_reconnectTimer, &QTimer::timeout, this, &StunPortMapper::connectToServer);
}

Net::StunPortMapper::~StunPortMapper()
{
    closeSocket();
}

bool Net::StunPortMapper::isSupported(const Protocol protocol)
{
#ifdef QBT_STUN_PORT_SHARING_SUPPORTED
#ifdef Q_OS_LINUX
    Q_UNUSED(protocol);
    return true;
#else
    // Delivering unicast datagrams to the "right" socket among several bound
    // to the same port is only well defined on Linux (connected socket wins)
    return (protocol == Protocol::TCP);
#endif
#else
    Q_UNUSED(protocol);
    return false;
#endif
}

Net::StunPortMapper::Protocol Net::StunPortMapper::protocol() const
{
    return m_protocol;
}

bool Net::StunPortMapper::isRunning() const
{
    return m_isRunning;
}

quint16 Net::StunPortMapper::localPort() const
{
    return m_localPort;
}

Net::Stun::Endpoint Net::StunPortMapper::mappedAddress() const
{
    return m_mappedAddress;
}

void Net::StunPortMapper::start(const quint16 localPort, const QList<Stun::Endpoint> &servers, const std::chrono::seconds keepAliveInterval)
{
    const bool isSameTarget = m_isRunning && (localPort == m_localPort);
    stop();

    // keep last known mapping while restarting on the same port
    if (!isSameTarget)
        setMappedAddress({});

    m_localPort = localPort;
    m_servers = servers;
    m_keepAliveInterval = std::max(keepAliveInterval, std::chrono::seconds(5));
    m_serverIndex = 0;
    m_failedAttempts = 0;
    m_lastError.clear();
    m_isRunning = true;

    if (!isSupported(m_protocol))
    {
        fail(tr("Sharing the listening port is not supported on this platform"));
        return;
    }

    if ((m_localPort == 0) || m_servers.isEmpty())
    {
        fail(tr("No usable STUN server"));
        return;
    }

    connectToServer();
}

void Net::StunPortMapper::stop()
{
    m_isRunning = false;
    m_transactionTimer->stop();
    m_keepAliveTimer->stop();
    m_reconnectTimer->stop();
    closeSocket();
}

void Net::StunPortMapper::connectToServer()
{
#ifdef QBT_STUN_PORT_SHARING_SUPPORTED
    if (!m_isRunning)
        return;

    if (m_failedAttempts >= m_servers.size())
    {
        fail(m_lastError);
        return;
    }

    closeSocket();

    const Stun::Endpoint &server = m_servers[m_serverIndex % m_servers.size()];

    QString error;
    const int fd = createSharedSocket(m_protocol, m_localPort, error);
    if (fd < 0)
    {
        fail(tr("Couldn't bind to local port %1: %2").arg(QString::number(m_localPort), error));
        return;
    }

    const int result = connectSocket(fd, server);
    if (result == 0)
    {
        onConnected(fd);
    }
    else if (result == EINPROGRESS)
    {
        m_pendingFD = fd;
        m_connectNotifier = new QSocketNotifier(fd, QSocketNotifier::Write, this);
        connect(m_connectNotifier, &QSocketNotifier::activated, this, &StunPortMapper::onConnectNotifierActivated);
        m_transactionTimer->start(TCP_CONNECT_TIMEOUT);
    }
    else
    {
        ::close(fd);
        tryNextServer(tr("Couldn't connect to %1: %2").arg(server.toString(), QString::fromLocal8Bit(std::strerror(result))));
    }
#endif
}

void Net::StunPortMapper::onConnectNotifierActivated()
{
#ifdef QBT_STUN_PORT_SHARING_SUPPORTED
    m_transactionTimer->stop();

    const int fd = std::exchange(m_pendingFD, -1);
    delete m_connectNotifier;
    m_connectNotifier = nullptr;

    int error = 0;
    socklen_t len = sizeof(error);
    if ((::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0) || (error != 0))
    {
        ::close(fd);
        const Stun::Endpoint &server = m_servers[m_serverIndex % m_servers.size()];
        tryNextServer(tr("Couldn't connect to %1: %2").arg(server.toString(), QString::fromLocal8Bit(std::strerror(error))));
        return;
    }

    onConnected(fd);
#endif
}

void Net::StunPortMapper::onConnected(const int fd)
{
    if (m_protocol == Protocol::TCP)
    {
        auto *socket = new QTcpSocket(this);
        socket->setSocketDescriptor(fd, QAbstractSocket::ConnectedState);
        connect(socket, &QTcpSocket::disconnected, this, &StunPortMapper::onDisconnected, Qt::QueuedConnection);
        m_socket = socket;
    }
    else
    {
        auto *socket = new QUdpSocket(this);
        socket->setSocketDescriptor(fd, QAbstractSocket::ConnectedState);
        m_socket = socket;
    }

    connect(m_socket, &QAbstractSocket::readyRead, this, &StunPortMapper::onReadyRead);
    m_buffer.clear();
    m_gotResponseOnConnection = false;
    sendBindingRequest();
}

void Net::StunPortMapper::sendBindingRequest()
{
    if (!m_socket)
        return;

    m_transactionID = Stun::generateTransactionID();
    m_request = Stun::buildBindingRequest(m_transactionID);
    m_attempt = 0;
    m_socket->write(m_request);
    m_transactionTimer->start((m_protocol == Protocol::TCP) ? TCP_RESPONSE_TIMEOUT : UDP_RETRANSMIT_INTERVAL);
}

void Net::StunPortMapper::onReadyRead()
{
    if (!m_socket)
        return;

    if (m_protocol == Protocol::UDP)
    {
        auto *socket = static_cast<QUdpSocket *>(m_socket);
        while (m_socket && socket->hasPendingDatagrams())
            processMessage(socket->receiveDatagram().data());
        return;
    }

    m_buffer.append(m_socket->readAll());
    while (m_socket)
    {
        const int size = Stun::messageSize(m_buffer);
        if (size < 0)
        {
            tryNextServer(tr("Invalid STUN response"));
            return;
        }
        if ((size == 0) || (m_buffer.size() < size))
            return;

        const QByteArray message = m_buffer.left(size);
        m_buffer.remove(0, size);
        processMessage(message);
    }
}

void Net::StunPortMapper::processMessage(const QByteArray &data)
{
    const std::optional<Stun::Message> message = Stun::parseMessage(data);
    if (!message || m_transactionID.isEmpty() || (message->transactionID != m_transactionID))
        return;

    m_transactionTimer->stop();
    m_transactionID.clear();

    if (!message->isSuccessResponse() || !message->reflexiveAddress().isValid())
    {
        tryNextServer(tr("STUN server returned error %1 %2").arg(QString::number(message->errorCode), message->errorReason));
        return;
    }

    m_gotResponseOnConnection = true;
    m_failedAttempts = 0;
    setMappedAddress(message->reflexiveAddress());

    if (m_protocol == Protocol::UDP)
    {
        // UDP socket is transient: while it exists, the service couldn't
        // (re)bind its own UDP socket to the port (libtorrent doesn't use
        // SO_REUSEADDR). The service's own traffic keeps UDP mapping alive.
        closeSocket();
        m_reconnectTimer->start(m_keepAliveInterval);
        return;
    }

    m_keepAliveTimer->start(m_keepAliveInterval);
}

void Net::StunPortMapper::onTransactionTimeout()
{
    const Stun::Endpoint &server = m_servers[m_serverIndex % m_servers.size()];

    if (m_pendingFD >= 0)
    {
        tryNextServer(tr("Connection to %1 timed out").arg(server.toString()));
        return;
    }

    if ((m_protocol == Protocol::UDP) && m_socket && (++m_attempt < UDP_MAX_ATTEMPTS))
    {
        m_socket->write(m_request);
        m_transactionTimer->start(UDP_RETRANSMIT_INTERVAL);
        return;
    }

    tryNextServer(tr("STUN server %1 didn't respond").arg(server.toString()));
}

void Net::StunPortMapper::onDisconnected()
{
    if (!m_isRunning || !m_socket)
        return;

    // Server closed the connection. Reconnect (using next server to avoid
    // any TIME_WAIT conflict on the same 4-tuple), the mapping is kept.
    const bool hadResponse = m_gotResponseOnConnection;
    closeSocket();
    ++m_serverIndex;
    if (hadResponse)
    {
        scheduleReconnect(RECONNECT_DELAY);
    }
    else
    {
        ++m_failedAttempts;
        m_lastError = tr("Connection closed by STUN server");
        scheduleReconnect(RETRY_DELAY);
    }
}

void Net::StunPortMapper::tryNextServer(const QString &reason)
{
    closeSocket();
    m_lastError = reason;
    ++m_failedAttempts;
    ++m_serverIndex;
    scheduleReconnect(RETRY_DELAY);
}

void Net::StunPortMapper::scheduleReconnect(const std::chrono::milliseconds delay)
{
    m_transactionTimer->stop();
    m_keepAliveTimer->stop();
    if (m_isRunning)
        m_reconnectTimer->start(delay);
}

void Net::StunPortMapper::closeSocket()
{
    m_transactionTimer->stop();
    m_keepAliveTimer->stop();
    m_transactionID.clear();

    delete m_connectNotifier;
    m_connectNotifier = nullptr;

#ifdef QBT_STUN_PORT_SHARING_SUPPORTED
    if (m_pendingFD >= 0)
        ::close(std::exchange(m_pendingFD, -1));
#endif

    if (m_socket)
    {
        m_socket->disconnect(this);
        m_socket->abort();
        m_socket->deleteLater();
        m_socket = nullptr;
    }
}

void Net::StunPortMapper::setMappedAddress(const Stun::Endpoint &address)
{
    if (address == m_mappedAddress)
        return;

    m_mappedAddress = address;
    emit mappingChanged(m_mappedAddress);
}

void Net::StunPortMapper::fail(const QString &message)
{
    stop();
    setMappedAddress({});
    emit errorOccurred(message);
}
