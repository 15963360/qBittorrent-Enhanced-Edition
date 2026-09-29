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

#pragma once

#include <chrono>

#include <QList>
#include <QObject>

#include "stunmessage.h"

class QAbstractSocket;
class QSocketNotifier;
class QTimer;

namespace Net
{
    // Discovers (and keeps alive) the public mapping of a *local* port that is
    // also used by another socket in this process (the BitTorrent listen port).
    //
    // Like natmap/Lucky "STUN traversal", the STUN socket is bound to the very
    // same local port as the service, so the NAT mapping reported by the STUN
    // server is exactly the one remote peers have to use to reach the service.
    // Binding to an already used port is only possible if every socket bound to
    // it allows address sharing:
    //  - Unix: SO_REUSEADDR/SO_REUSEPORT is enabled on the service sockets owned
    //    by this process first (see enableAddressSharing()).
    //  - Windows: the service must not use SO_EXCLUSIVEADDRUSE; libtorrent does
    //    unless its (patched) `listen_socket_shared` setting is enabled. The
    //    STUN socket is then bound with SO_REUSEADDR.
    //
    // TCP: a long-lived connection to the STUN server is kept open and a new
    //      Binding request is sent every keep-alive interval, which both keeps
    //      the NAT session alive and detects mapping changes.
    // UDP: a short-lived *connected* UDP socket is used so that the kernel only
    //      delivers the STUN server's datagrams to it; all other datagrams keep
    //      going to the service's unconnected socket (Linux only; Windows
    //      delivers them to the first bound socket). The socket is closed
    //      right after each transaction so that it never prevents the
    //      service from re-binding its own socket.
    class StunPortMapper final : public QObject
    {
        Q_OBJECT
        Q_DISABLE_COPY_MOVE(StunPortMapper)

    public:
        enum class Protocol
        {
            TCP,
            UDP
        };

        explicit StunPortMapper(Protocol protocol, QObject *parent = nullptr);
        ~StunPortMapper() override;

        static bool isSupported(Protocol protocol);

        Protocol protocol() const;
        bool isRunning() const;
        quint16 localPort() const;
        Stun::Endpoint mappedAddress() const;

        void start(quint16 localPort, const QList<Stun::Endpoint> &servers, std::chrono::seconds keepAliveInterval);
        void stop();

    signals:
        // Invalid endpoint means the mapping is lost
        void mappingChanged(const Net::Stun::Endpoint &mappedAddress);
        // Emitted when mapping can't be established (the mapper stops)
        void errorOccurred(const QString &message);

    private:
        void connectToServer();
        void onConnectNotifierActivated();
        void onConnected(qintptr fd);
        void sendBindingRequest();
        void onReadyRead();
        void processMessage(const QByteArray &data);
        void onTransactionTimeout();
        void onDisconnected();
        void tryNextServer(const QString &reason);
        void scheduleReconnect(std::chrono::milliseconds delay);
        void closeSocket();
        void setMappedAddress(const Stun::Endpoint &address);
        void fail(const QString &message);

        const Protocol m_protocol;
        bool m_isRunning = false;
        quint16 m_localPort = 0;
        QList<Stun::Endpoint> m_servers;
        std::chrono::seconds m_keepAliveInterval {25};

        int m_serverIndex = 0;
        int m_failedAttempts = 0;
        bool m_gotResponseOnConnection = false;
        QString m_lastError;

        qintptr m_pendingFD = -1;
        QSocketNotifier *m_connectNotifier = nullptr;
        QAbstractSocket *m_socket = nullptr;
        QByteArray m_buffer;

        QByteArray m_transactionID;
        QByteArray m_request;
        int m_attempt = 0;

        QTimer *m_transactionTimer = nullptr;
        QTimer *m_keepAliveTimer = nullptr;
        QTimer *m_reconnectTimer = nullptr;

        Stun::Endpoint m_mappedAddress;
    };
}
