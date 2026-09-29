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

#include "stunnattraversal.h"

#include <QHostAddress>
#include <QHostInfo>
#include <QLocale>
#include <QTimer>

#include "base/global.h"
#include "base/logger.h"
#include "base/net/stunportmapper.h"

using namespace std::chrono_literals;

namespace
{
    constexpr quint16 DEFAULT_STUN_PORT = 3478;
    // NAT UDP session timeouts can be as short as 30 seconds
    constexpr std::chrono::seconds KEEPALIVE_INTERVAL = 25s;

    struct ServerAddress
    {
        QString host;
        quint16 port = 0;
    };

    ServerAddress parseServer(QString server)
    {
        server = server.trimmed();
        if (server.startsWith(u"stun:", Qt::CaseInsensitive))
            server = server.mid(5);
        if (server.isEmpty())
            return {};

        // IPv6 literals are not useful here since NAT traversal is an IPv4 matter
        const qsizetype colonPos = server.lastIndexOf(u':');
        if (colonPos < 0)
            return {server, DEFAULT_STUN_PORT};

        bool ok = false;
        const uint port = server.mid(colonPos + 1).toUInt(&ok);
        if (!ok || (port == 0) || (port > 65535))
            return {};
        return {server.left(colonPos), static_cast<quint16>(port)};
    }

    QString protocolName(const Net::StunPortMapper *mapper)
    {
        return (mapper->protocol() == Net::StunPortMapper::Protocol::TCP) ? u"TCP"_s : u"UDP"_s;
    }
}

QString BitTorrent::StunStatus::publicAddressString() const
{
    if (tcpMappedAddress.isValid())
        return tcpMappedAddress.toString();
    if (udpMappedAddress.isValid())
        return udpMappedAddress.toString();
    return {};
}

QString BitTorrent::StunStatus::toolTipText() const
{
    if (!isEnabled)
        return {};

    const QString none = StunNatTraversal::tr("N/A");
    QStringList lines;
    lines << StunNatTraversal::tr("STUN NAT type: %1").arg(Net::natTypeToString(natType));
    lines << StunNatTraversal::tr("STUN public address (TCP): %1")
        .arg(tcpMappedAddress.isValid() ? tcpMappedAddress.toString() : none);
    lines << StunNatTraversal::tr("STUN public address (UDP): %1")
        .arg(udpMappedAddress.isValid() ? udpMappedAddress.toString() : none);
    if (externalPort > 0)
        lines << StunNatTraversal::tr("Port announced to trackers: %1").arg(QString::number(externalPort));
    lines << StunNatTraversal::tr("STUN last check: %1")
        .arg(lastCheckTime.isValid() ? QLocale().toString(lastCheckTime, QLocale::ShortFormat) : none);
    if (!lastError.isEmpty())
        lines << StunNatTraversal::tr("STUN last error: %1").arg(lastError);
    return lines.join(u'\n');
}

BitTorrent::StunNatTraversal::StunNatTraversal(QObject *parent)
    : QObject(parent)
    , m_checkTimer {new QTimer(this)}
    , m_natTypeDetector {new Net::StunNatTypeDetector(this)}
    , m_tcpMapper {new Net::StunPortMapper(Net::StunPortMapper::Protocol::TCP, this)}
    , m_udpMapper {new Net::StunPortMapper(Net::StunPortMapper::Protocol::UDP, this)}
{
    connect(m_checkTimer, &QTimer::timeout, this, &StunNatTraversal::checkNow);
    connect(m_natTypeDetector, &Net::StunNatTypeDetector::finished, this, &StunNatTraversal::onNatDetectionFinished);

    for (Net::StunPortMapper *mapper : {m_tcpMapper, m_udpMapper})
    {
        connect(mapper, &Net::StunPortMapper::mappingChanged, this, [this, mapper](const Net::Stun::Endpoint &address)
        {
            onMappingChanged(mapper, address);
        });
        connect(mapper, &Net::StunPortMapper::errorOccurred, this, [this, mapper](const QString &message)
        {
            onMapperError(mapper, message);
        });
    }
}

BitTorrent::StunNatTraversal::~StunNatTraversal()
{
    // avoid emitting signals to a (partially) destroyed session
    disconnect(this, nullptr, nullptr, nullptr);
    stop();
}

QStringList BitTorrent::StunNatTraversal::defaultServers()
{
    return {
        // Primary servers (UDP + TCP, reachable from mainland China)
        u"stun.miwifi.com:3478"_s,
        u"stun.chat.bilibili.com:3478"_s,
        u"stun.l.google.com:19302"_s,
        // Fallback servers (UDP + TCP)
        u"turn.cloudflare.com:3478"_s,
        u"stun.nextcloud.com:3478"_s
    };
}

void BitTorrent::StunNatTraversal::configure(const bool enabled, const quint16 listenPort
        , const QStringList &servers, const std::chrono::seconds checkInterval)
{
    const std::chrono::seconds interval = std::max(checkInterval, std::chrono::seconds(30));
    if ((enabled == m_isEnabled) && (listenPort == m_listenPort)
        && (servers == m_servers) && (interval == m_checkInterval))
    {
        return;
    }

    const bool wasEnabled = m_isEnabled;
    m_isEnabled = enabled;
    m_listenPort = listenPort;
    m_servers = servers;
    m_checkInterval = interval;

    stop();

    if (m_isEnabled)
    {
        if (!wasEnabled)
            LogMsg(tr("STUN NAT traversal: ON. Servers: %1").arg(m_servers.join(u", ")), Log::INFO);
        start();
    }
    else if (wasEnabled)
    {
        LogMsg(tr("STUN NAT traversal: OFF"), Log::INFO);
    }
}

void BitTorrent::StunNatTraversal::start()
{
    m_isNatTypeDetected = false;
    m_status = {};
    m_status.isEnabled = true;
    m_status.listenPort = m_listenPort;
    emit statusChanged();

    m_checkTimer->start(m_checkInterval);
    checkNow();
}

void BitTorrent::StunNatTraversal::stop()
{
    m_checkTimer->stop();
    ++m_lookupGeneration;
    m_pendingLookups = 0;
    m_natTypeDetector->abort();
    m_tcpMapper->stop();
    m_udpMapper->stop();

    const bool hadExternalPort = (m_status.externalPort != 0);
    m_status = {};
    m_status.isEnabled = m_isEnabled;
    emit statusChanged();
    if (hadExternalPort)
        emit externalPortChanged(0);
}

void BitTorrent::StunNatTraversal::checkNow()
{
    if (!m_isEnabled || (m_pendingLookups > 0) || m_natTypeDetector->isRunning())
        return;

    m_status.isChecking = true;
    m_status.lastCheckTime = QDateTime::currentDateTime();
    emit statusChanged();

    resolveServers();
}

void BitTorrent::StunNatTraversal::resolveServers()
{
    const int generation = ++m_lookupGeneration;
    m_lookupResults = QList<QList<Net::Stun::Endpoint>>(m_servers.size());
    m_pendingLookups = 0;

    QList<std::pair<int, ServerAddress>> lookups;
    for (int i = 0; i < m_servers.size(); ++i)
    {
        const ServerAddress server = parseServer(m_servers[i]);
        if (server.host.isEmpty())
            continue;

        if (const QHostAddress address {server.host}; !address.isNull())
        {
            if (address.protocol() == QAbstractSocket::IPv4Protocol)
                m_lookupResults[i].append({address, server.port});
            continue;
        }

        lookups.append({i, server});
    }

    if (lookups.isEmpty())
    {
        onServersResolved();
        return;
    }

    m_pendingLookups = lookups.size();
    for (const auto &[index, server] : asConst(lookups))
    {
        QHostInfo::lookupHost(server.host, this, [this, generation, index, port = server.port](const QHostInfo &hostInfo)
        {
            if (generation != m_lookupGeneration)
                return;

            // one address per server is enough, prefer IPv4
            for (const QHostAddress &address : asConst(hostInfo.addresses()))
            {
                if (address.protocol() == QAbstractSocket::IPv4Protocol)
                {
                    m_lookupResults[index].append({address, port});
                    break;
                }
            }

            if (--m_pendingLookups == 0)
                onServersResolved();
        });
    }
}

void BitTorrent::StunNatTraversal::onServersResolved()
{
    m_resolvedServers.clear();
    for (const QList<Net::Stun::Endpoint> &endpoints : asConst(m_lookupResults))
    {
        for (const Net::Stun::Endpoint &endpoint : endpoints)
        {
            if (!m_resolvedServers.contains(endpoint))
                m_resolvedServers.append(endpoint);
        }
    }

    if (m_resolvedServers.isEmpty())
    {
        m_status.isChecking = false;
        setLastError(tr("Couldn't resolve any STUN server"));
        return;
    }

    m_natTypeDetector->start(m_resolvedServers);
    ensureMappersRunning();
}

void BitTorrent::StunNatTraversal::ensureMappersRunning()
{
    if (m_listenPort == 0)
        return;

    for (Net::StunPortMapper *mapper : {m_tcpMapper, m_udpMapper})
    {
        if (!Net::StunPortMapper::isSupported(mapper->protocol()))
            continue;

        // A running mapper keeps its mapping alive and up to date by itself
        if (!mapper->isRunning() || (mapper->localPort() != m_listenPort))
            mapper->start(m_listenPort, m_resolvedServers, KEEPALIVE_INTERVAL);
    }
}

void BitTorrent::StunNatTraversal::onNatDetectionFinished(const Net::NatDetectionResult &result)
{
    const Net::NatType oldType = m_status.natType;
    m_isNatTypeDetected = true;
    m_status.isChecking = false;
    m_status.natType = result.type;
    m_status.natAddress = result.mappedAddress;

    if (result.type == Net::NatType::UdpBlocked)
    {
        setLastError(tr("No STUN server responded over UDP"));
    }
    else if (result.type != oldType)
    {
        LogMsg(tr("STUN: detected NAT type: %1. Public address: %2. Server: %3")
            .arg(Net::natTypeToString(result.type), result.mappedAddress.toString(), result.server.toString()), Log::INFO);
        if (result.type == Net::NatType::Symmetric)
        {
            LogMsg(tr("STUN: symmetric NAT detected, the public mapping differs per destination and can't be announced")
                , Log::WARNING);
        }
    }

    emit statusChanged();
    updateExternalPort();
}

void BitTorrent::StunNatTraversal::onMappingChanged(Net::StunPortMapper *mapper, const Net::Stun::Endpoint &address)
{
    Net::Stun::Endpoint &stored = (mapper == m_tcpMapper) ? m_status.tcpMappedAddress : m_status.udpMappedAddress;
    const Net::Stun::Endpoint oldAddress = stored;
    stored = address;

    if (address.isValid())
    {
        m_status.lastError.clear();
        if (oldAddress.isValid())
        {
            LogMsg(tr("STUN: %1 mapping of listening port %2 changed: %3 -> %4")
                .arg(protocolName(mapper), QString::number(m_listenPort), oldAddress.toString(), address.toString()), Log::INFO);
        }
        else
        {
            LogMsg(tr("STUN: %1 listening port %2 is mapped to public address %3")
                .arg(protocolName(mapper), QString::number(m_listenPort), address.toString()), Log::INFO);
        }
    }

    emit statusChanged();
    updateExternalPort();
}

void BitTorrent::StunNatTraversal::onMapperError(Net::StunPortMapper *mapper, const QString &message)
{
    setLastError(tr("%1 mapping failed: %2").arg(protocolName(mapper), message));
}

void BitTorrent::StunNatTraversal::updateExternalPort()
{
    quint16 port = 0;
    // Wait for NAT type detection to avoid announcing a mapping that turns out
    // to be unusable (symmetric NAT)
    if (m_isNatTypeDetected && (m_status.natType != Net::NatType::Symmetric))
    {
        // TCP mapping is preferred since trackers only accept a single port
        // and TCP is supported by every BitTorrent client
        if (m_status.tcpMappedAddress.isValid())
            port = m_status.tcpMappedAddress.port;
        else if (m_status.udpMappedAddress.isValid())
            port = m_status.udpMappedAddress.port;
    }

    if (port == m_status.externalPort)
        return;

    m_status.externalPort = port;
    emit statusChanged();
    emit externalPortChanged(port);
}

void BitTorrent::StunNatTraversal::setLastError(const QString &error)
{
    // Don't flood the log with the same error on every check
    if (error != m_status.lastError)
        LogMsg(tr("STUN: %1").arg(error), Log::WARNING);

    m_status.lastError = error;
    emit statusChanged();
}


BitTorrent::StunStatus BitTorrent::StunNatTraversal::status() const
{
    return m_status;
}

quint16 BitTorrent::StunNatTraversal::externalPort() const
{
    return m_status.externalPort;
}
