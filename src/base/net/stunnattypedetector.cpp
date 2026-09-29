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

#include "stunnattypedetector.h"

#include <chrono>
#include <iterator>
#include <utility>

#include <QNetworkDatagram>
#include <QNetworkInterface>
#include <QTimer>
#include <QUdpSocket>

#include "base/global.h"

using namespace std::chrono_literals;

namespace
{
    // RFC 5389 section 7.2.1 style retransmission schedule (shortened)
    constexpr std::chrono::milliseconds RETRANSMIT_INTERVALS[] = {500ms, 1000ms, 1000ms};
    constexpr int MAX_ATTEMPTS = static_cast<int>(std::size(RETRANSMIT_INTERVALS));

    bool isLocalAddress(const QHostAddress &address)
    {
        return QNetworkInterface::allAddresses().contains(address);
    }
}

QString Net::natTypeToString(const NatType type)
{
    switch (type)
    {
    case NatType::UdpBlocked:
        return StunNatTypeDetector::tr("UDP blocked");
    case NatType::OpenInternet:
        return StunNatTypeDetector::tr("Open Internet (no NAT)");
    case NatType::FullCone:
        return StunNatTypeDetector::tr("Full cone NAT (NAT1)");
    case NatType::RestrictedCone:
        return StunNatTypeDetector::tr("Restricted cone NAT (NAT2)");
    case NatType::PortRestrictedCone:
        return StunNatTypeDetector::tr("Port restricted cone NAT (NAT3)");
    case NatType::Symmetric:
        return StunNatTypeDetector::tr("Symmetric NAT (NAT4)");
    case NatType::ConeUnknownFiltering:
        return StunNatTypeDetector::tr("Cone NAT (filtering unknown)");
    case NatType::Unknown:
    default:
        return StunNatTypeDetector::tr("Unknown");
    }
}

QString Net::natTypeToKey(const NatType type)
{
    switch (type)
    {
    case NatType::UdpBlocked:
        return u"udp_blocked"_s;
    case NatType::OpenInternet:
        return u"open"_s;
    case NatType::FullCone:
        return u"full_cone"_s;
    case NatType::RestrictedCone:
        return u"restricted_cone"_s;
    case NatType::PortRestrictedCone:
        return u"port_restricted_cone"_s;
    case NatType::Symmetric:
        return u"symmetric"_s;
    case NatType::ConeUnknownFiltering:
        return u"cone"_s;
    case NatType::Unknown:
    default:
        return u"unknown"_s;
    }
}

Net::StunNatTypeDetector::StunNatTypeDetector(QObject *parent)
    : QObject(parent)
    , m_retransmitTimer {new QTimer(this)}
{
    m_retransmitTimer->setSingleShot(true);
    connect(m_retransmitTimer, &QTimer::timeout, this, &StunNatTypeDetector::retransmit);
}

Net::StunNatTypeDetector::~StunNatTypeDetector()
{
    abort();
}

bool Net::StunNatTypeDetector::isRunning() const
{
    return (m_socket != nullptr);
}

void Net::StunNatTypeDetector::start(const QList<Stun::Endpoint> &servers)
{
    abort();

    m_servers = servers;
    m_result = {};
    m_primaryServer = {};
    m_otherAddress = {};

    if (m_servers.isEmpty())
    {
        // report asynchronously so that callers can rely on signal being emitted after start() returns
        QMetaObject::invokeMethod(this, [this] { emit finished(m_result); }, Qt::QueuedConnection);
        return;
    }

    m_socket = new QUdpSocket(this);
    if (!m_socket->bind(QHostAddress::AnyIPv4, 0))
    {
        delete m_socket;
        m_socket = nullptr;
        QMetaObject::invokeMethod(this, [this] { emit finished(m_result); }, Qt::QueuedConnection);
        return;
    }
    connect(m_socket, &QUdpSocket::readyRead, this, &StunNatTypeDetector::readPendingDatagrams);

    findPrimaryServer(0);
}

void Net::StunNatTypeDetector::abort()
{
    m_retransmitTimer->stop();
    m_handler = nullptr;
    if (m_socket)
    {
        m_socket->disconnect(this);
        m_socket->close();
        m_socket->deleteLater();
        m_socket = nullptr;
    }
}

void Net::StunNatTypeDetector::sendRequest(const Stun::Endpoint &target, const bool changeIP, const bool changePort, ResponseHandler handler)
{
    m_target = target;
    m_transactionID = Stun::generateTransactionID();
    m_request = Stun::buildBindingRequest(m_transactionID, changeIP, changePort);
    m_handler = std::move(handler);
    m_attempt = 0;

    m_socket->writeDatagram(m_request, m_target.address, m_target.port);
    m_retransmitTimer->start(RETRANSMIT_INTERVALS[0]);
}

void Net::StunNatTypeDetector::retransmit()
{
    if (!m_socket || !m_handler)
        return;

    ++m_attempt;
    if (m_attempt >= MAX_ATTEMPTS)
    {
        const ResponseHandler handler = std::exchange(m_handler, nullptr);
        m_transactionID.clear();
        handler(std::nullopt);
        return;
    }

    m_socket->writeDatagram(m_request, m_target.address, m_target.port);
    m_retransmitTimer->start(RETRANSMIT_INTERVALS[m_attempt]);
}

void Net::StunNatTypeDetector::readPendingDatagrams()
{
    while (m_socket && m_socket->hasPendingDatagrams())
    {
        const QNetworkDatagram datagram = m_socket->receiveDatagram();
        const std::optional<Stun::Message> message = Stun::parseMessage(datagram.data());
        if (!message || !m_handler || (message->transactionID != m_transactionID))
            continue;
        if (!message->isSuccessResponse() && !message->isErrorResponse())
            continue;

        m_retransmitTimer->stop();
        m_transactionID.clear();
        const ResponseHandler handler = std::exchange(m_handler, nullptr);
        if (message->isSuccessResponse() && message->reflexiveAddress().isValid())
            handler(message);
        else
            handler(std::nullopt);
    }
}

// Test I: find the first server that answers a plain Binding request
void Net::StunNatTypeDetector::findPrimaryServer(const int serverIndex)
{
    if (serverIndex >= m_servers.size())
    {
        finish(NatType::UdpBlocked);
        return;
    }

    sendRequest(m_servers[serverIndex], false, false, [this, serverIndex](const std::optional<Stun::Message> &response)
    {
        if (response)
            onPrimaryServerFound(serverIndex, *response);
        else
            findPrimaryServer(serverIndex + 1);
    });
}

void Net::StunNatTypeDetector::onPrimaryServerFound(const int serverIndex, const Stun::Message &response)
{
    const Stun::Endpoint mapped = response.reflexiveAddress();
    m_primaryServer = m_servers[serverIndex];
    m_result.server = m_primaryServer;
    m_result.mappedAddress = mapped;

    if (isLocalAddress(mapped.address) && (mapped.port == m_socket->localPort()))
    {
        finish(NatType::OpenInternet);
        return;
    }

    const Stun::Endpoint other = response.otherAddress;
    if (other.isValid() && (other.address != m_primaryServer.address))
    {
        m_otherAddress = other;
        runFilteringTests(mapped);
    }
    else
    {
        runSecondServerMappingTest(serverIndex + 1, mapped);
    }
}

// RFC 5780 section 4.3/4.4 (RFC 3489 tests II and III)
void Net::StunNatTypeDetector::runFilteringTests(const Stun::Endpoint &mapped)
{
    // Test II: ask server to respond from alternate IP and port
    sendRequest(m_primaryServer, true, true, [this, mapped](const std::optional<Stun::Message> &response)
    {
        if (response)
        {
            m_result.supportsChangeRequest = true;
            finish(NatType::FullCone);
            return;
        }

        // Mapping test: send to alternate IP, primary port
        const Stun::Endpoint alternate {m_otherAddress.address, m_primaryServer.port};
        sendRequest(alternate, false, false, [this, mapped](const std::optional<Stun::Message> &response)
        {
            if (!response)
            {
                // Server advertised alternate address but it doesn't answer
                finish(NatType::Unknown);
                return;
            }

            if (response->reflexiveAddress() != mapped)
            {
                finish(NatType::Symmetric);
                return;
            }

            // Test III: ask server to respond from alternate port only
            sendRequest(m_primaryServer, false, true, [this](const std::optional<Stun::Message> &response)
            {
                if (response)
                    m_result.supportsChangeRequest = true;
                finish(response ? NatType::RestrictedCone : NatType::PortRestrictedCone);
            });
        });
    });
}

// Fallback for servers without RFC 5780 support (e.g. stun.l.google.com):
// compare the mapping observed by another server (with a different IP).
void Net::StunNatTypeDetector::runSecondServerMappingTest(const int serverIndex, const Stun::Endpoint &mapped)
{
    int index = serverIndex;
    while ((index < m_servers.size()) && (m_servers[index].address == m_primaryServer.address))
        ++index;

    if (index >= m_servers.size())
    {
        finish(NatType::Unknown);
        return;
    }

    sendRequest(m_servers[index], false, false, [this, index, mapped](const std::optional<Stun::Message> &response)
    {
        if (!response)
        {
            runSecondServerMappingTest(index + 1, mapped);
            return;
        }

        finish((response->reflexiveAddress() == mapped) ? NatType::ConeUnknownFiltering : NatType::Symmetric);
    });
}

void Net::StunNatTypeDetector::finish(const NatType type)
{
    m_result.type = type;
    abort();
    emit finished(m_result);
}
