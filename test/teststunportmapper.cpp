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

#include <chrono>

#include <libtorrent/session.hpp>
#include <libtorrent/settings_pack.hpp>

#include <QByteArray>
#include <QHostAddress>
#include <QNetworkDatagram>
#include <QObject>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <QUdpSocket>
#include <QtEndian>

#include "base/global.h"
#include "base/net/stunmessage.h"
#include "base/net/stunportmapper.h"

using namespace std::chrono_literals;

namespace
{
    // Builds a Binding success response reflecting `source` (like a STUN server)
    QByteArray buildResponse(const QByteArray &request, const QHostAddress &source, const quint16 port)
    {
        const auto message = Net::Stun::parseMessage(request);
        if (!message || (message->type != Net::Stun::BindingRequest))
            return {};

        char attr[12];
        qToBigEndian<quint16>(Net::Stun::XorMappedAddress, attr);
        qToBigEndian<quint16>(8, attr + 2);
        attr[4] = 0;
        attr[5] = 1;    // IPv4
        qToBigEndian<quint16>(static_cast<quint16>(port ^ (Net::Stun::MAGIC_COOKIE >> 16)), attr + 6);
        qToBigEndian<quint32>(source.toIPv4Address() ^ Net::Stun::MAGIC_COOKIE, attr + 8);

        char header[8];
        qToBigEndian<quint16>(Net::Stun::BindingSuccessResponse, header);
        qToBigEndian<quint16>(sizeof(attr), header + 2);
        qToBigEndian<quint32>(Net::Stun::MAGIC_COOKIE, header + 4);
        return QByteArray(header, sizeof(header)) + message->transactionID + QByteArray(attr, sizeof(attr));
    }

    // Minimal local STUN server (UDP + TCP) on 127.0.0.1
    class LocalStunServer final : public QObject
    {
    public:
        LocalStunServer()
        {
            m_udp.bind(QHostAddress::LocalHost, 0);
            connect(&m_udp, &QUdpSocket::readyRead, this, [this]
            {
                while (m_udp.hasPendingDatagrams())
                {
                    const QNetworkDatagram datagram = m_udp.receiveDatagram();
                    const QByteArray response = buildResponse(datagram.data(), datagram.senderAddress()
                        , static_cast<quint16>(datagram.senderPort()));
                    if (!response.isEmpty())
                        m_udp.writeDatagram(response, datagram.senderAddress(), static_cast<quint16>(datagram.senderPort()));
                }
            });

            m_tcp.listen(QHostAddress::LocalHost, 0);
            connect(&m_tcp, &QTcpServer::newConnection, this, [this]
            {
                while (QTcpSocket *client = m_tcp.nextPendingConnection())
                {
                    ++m_tcpConnections;
                    connect(client, &QTcpSocket::readyRead, client, [client]
                    {
                        // test requests have no attributes
                        while (client->bytesAvailable() >= Net::Stun::HEADER_SIZE)
                        {
                            const QByteArray request = client->read(Net::Stun::HEADER_SIZE);
                            client->write(buildResponse(request, client->peerAddress(), client->peerPort()));
                        }
                    });
                }
            });
        }

        Net::Stun::Endpoint udpEndpoint() const { return {QHostAddress(QHostAddress::LocalHost), m_udp.localPort()}; }
        Net::Stun::Endpoint tcpEndpoint() const { return {QHostAddress(QHostAddress::LocalHost), m_tcp.serverPort()}; }
        int tcpConnections() const { return m_tcpConnections; }

    private:
        QUdpSocket m_udp;
        QTcpServer m_tcp;
        int m_tcpConnections = 0;
    };

    lt::settings_pack sessionSettings()
    {
        lt::settings_pack pack;
        pack.set_str(lt::settings_pack::listen_interfaces, "127.0.0.1:0");
        pack.set_bool(lt::settings_pack::enable_dht, false);
        pack.set_bool(lt::settings_pack::enable_lsd, false);
        pack.set_bool(lt::settings_pack::enable_upnp, false);
        pack.set_bool(lt::settings_pack::enable_natpmp, false);
#ifdef TORRENT_HAS_LISTEN_SOCKET_SHARED
        // what qBittorrent enables on Windows when STUN is used
        pack.set_bool(lt::settings_pack::listen_socket_shared, true);
#endif
        return pack;
    }

    Net::Stun::Endpoint waitForMapping(Net::StunPortMapper &mapper, QSignalSpy &errorSpy)
    {
        QSignalSpy spy {&mapper, &Net::StunPortMapper::mappingChanged};
        if (!mapper.mappedAddress().isValid() && errorSpy.isEmpty())
            spy.wait(10'000);
        return mapper.mappedAddress();
    }
}

// Verifies that STUN requests are sent from the *listening port of a real
// libtorrent session* (the core requirement of STUN NAT traversal) and that
// libtorrent keeps accepting incoming connections on that port.
class TestStunPortMapper final : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(TestStunPortMapper)

public:
    TestStunPortMapper() = default;

private slots:
    void testTcpMappingSharesLibtorrentListenPort() const
    {
        if (!Net::StunPortMapper::isSupported(Net::StunPortMapper::Protocol::TCP))
            QSKIP("Listen port sharing is not supported on this platform");
#if defined(Q_OS_WIN) && !defined(TORRENT_HAS_LISTEN_SOCKET_SHARED)
        QSKIP("libtorrent without listen_socket_shared support");
#endif

        lt::session session {sessionSettings()};
        QTRY_VERIFY_WITH_TIMEOUT(session.listen_port() != 0, 10'000);
        const quint16 listenPort = session.listen_port();

        LocalStunServer server;
        Net::StunPortMapper mapper {Net::StunPortMapper::Protocol::TCP};
        QSignalSpy errorSpy {&mapper, &Net::StunPortMapper::errorOccurred};
        mapper.start(listenPort, {server.tcpEndpoint()}, 5s);

        const Net::Stun::Endpoint mapped = waitForMapping(mapper, errorSpy);
        if (!errorSpy.isEmpty())
            qWarning() << "mapper error:" << errorSpy.first().first().toString();
        QVERIFY(errorSpy.isEmpty());
        QCOMPARE(mapped.address, QHostAddress(QHostAddress::LocalHost));
        QCOMPARE(mapped.port, listenPort);

        // libtorrent still accepts incoming connections on its listen port
        QTcpSocket peer;
        peer.connectToHost(QHostAddress::LocalHost, listenPort);
        QVERIFY(peer.waitForConnected(5000));

        // keep-alive is sent over the same connection
        QTest::qWait(6000);
        QVERIFY(mapper.isRunning());
        QCOMPARE(server.tcpConnections(), 1);
        QCOMPARE(mapper.mappedAddress().port, listenPort);
    }

    void testUdpMappingSharesLibtorrentListenPort() const
    {
        if (!Net::StunPortMapper::isSupported(Net::StunPortMapper::Protocol::UDP))
            QSKIP("UDP listen port sharing is not supported on this platform");
#if defined(Q_OS_WIN) && !defined(TORRENT_HAS_LISTEN_SOCKET_SHARED)
        QSKIP("libtorrent without listen_socket_shared support");
#endif

        lt::session session {sessionSettings()};
        QTRY_VERIFY_WITH_TIMEOUT(session.listen_port() != 0, 10'000);
        const quint16 listenPort = session.listen_port();

        LocalStunServer server;
        Net::StunPortMapper mapper {Net::StunPortMapper::Protocol::UDP};
        QSignalSpy errorSpy {&mapper, &Net::StunPortMapper::errorOccurred};
        mapper.start(listenPort, {server.udpEndpoint()}, 5s);

        const Net::Stun::Endpoint mapped = waitForMapping(mapper, errorSpy);
        if (!errorSpy.isEmpty())
            qWarning() << "mapper error:" << errorSpy.first().first().toString();
#ifdef Q_OS_WIN
        // Best effort on Windows: the reply may be delivered to libtorrent's socket
        qInfo() << "UDP mapping on Windows:" << mapped.toString();
        if (!mapped.isValid())
            QSKIP("UDP reply was not delivered to the STUN socket (best effort on Windows)");
#endif
        QCOMPARE(mapped.address, QHostAddress(QHostAddress::LocalHost));
        QCOMPARE(mapped.port, listenPort);
    }
};

QTEST_GUILESS_MAIN(TestStunPortMapper)
#include "teststunportmapper.moc"
