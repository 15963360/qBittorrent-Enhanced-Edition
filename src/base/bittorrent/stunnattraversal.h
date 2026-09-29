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

#include <QDateTime>
#include <QList>
#include <QObject>
#include <QStringList>

#include "base/net/stunmessage.h"
#include "base/net/stunnattypedetector.h"

class QTimer;

namespace Net
{
    class StunPortMapper;
}

namespace BitTorrent
{
    struct StunStatus
    {
        bool isEnabled = false;
        bool isChecking = false;
        Net::NatType natType = Net::NatType::Unknown;
        // public address of an ephemeral UDP socket (NAT type detection)
        Net::Stun::Endpoint natAddress;
        // public mappings of the BitTorrent listening port
        Net::Stun::Endpoint tcpMappedAddress;
        Net::Stun::Endpoint udpMappedAddress;
        quint16 listenPort = 0;
        // port reported to trackers/DHT because of STUN (0 if none)
        quint16 externalPort = 0;
        QDateTime lastCheckTime;
        QString lastError;

        QString publicAddressString() const;
        QString toolTipText() const;
    };

    // Native STUN based NAT traversal helper:
    //  - periodically detects NAT type (UDP, RFC 5780/3489 tests)
    //  - discovers and keeps alive the public TCP/UDP mapping of the BitTorrent
    //    listening port (see Net::StunPortMapper)
    //  - reports the public port that should be announced to trackers/DHT
    class StunNatTraversal final : public QObject
    {
        Q_OBJECT
        Q_DISABLE_COPY_MOVE(StunNatTraversal)

    public:
        explicit StunNatTraversal(QObject *parent = nullptr);
        ~StunNatTraversal() override;

        static QStringList defaultServers();

        // (Re)starts STUN traversal if parameters changed. Pass `enabled` = false to stop.
        void configure(bool enabled, quint16 listenPort, const QStringList &servers, std::chrono::seconds checkInterval);
        void checkNow();

        StunStatus status() const;
        // Public port peers should use to reach the listening port, 0 if unknown/unusable
        quint16 externalPort() const;

    signals:
        void statusChanged();
        void externalPortChanged(quint16 port);

    private:
        void start();
        void stop();
        void resolveServers();
        void onServersResolved();
        void onNatDetectionFinished(const Net::NatDetectionResult &result);
        void onMappingChanged(Net::StunPortMapper *mapper, const Net::Stun::Endpoint &address);
        void onMapperError(Net::StunPortMapper *mapper, const QString &message);
        void ensureMappersRunning();
        void updateExternalPort();
        void setLastError(const QString &error);

        bool m_isEnabled = false;
        quint16 m_listenPort = 0;
        QStringList m_servers;
        std::chrono::seconds m_checkInterval {300};

        QTimer *m_checkTimer = nullptr;
        Net::StunNatTypeDetector *m_natTypeDetector = nullptr;
        Net::StunPortMapper *m_tcpMapper = nullptr;
        Net::StunPortMapper *m_udpMapper = nullptr;

        bool m_isNatTypeDetected = false;
        int m_pendingLookups = 0;
        int m_lookupGeneration = 0;
        QList<QList<Net::Stun::Endpoint>> m_lookupResults;
        QList<Net::Stun::Endpoint> m_resolvedServers;

        StunStatus m_status;
    };
}
