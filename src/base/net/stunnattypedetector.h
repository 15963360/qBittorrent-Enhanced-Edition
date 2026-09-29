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

#include <functional>
#include <optional>

#include <QList>
#include <QObject>

#include "stunmessage.h"

class QTimer;
class QUdpSocket;

namespace Net
{
    enum class NatType
    {
        Unknown,
        UdpBlocked,
        OpenInternet,
        FullCone,
        RestrictedCone,
        PortRestrictedCone,
        Symmetric,
        ConeUnknownFiltering    // endpoint-independent mapping, filtering behavior not detectable
    };

    QString natTypeToString(NatType type);
    // Stable, non translated identifier (used by WebAPI)
    QString natTypeToKey(NatType type);

    struct NatDetectionResult
    {
        NatType type = NatType::Unknown;
        Stun::Endpoint mappedAddress;   // public address seen by the first responding server
        Stun::Endpoint server;          // first responding server
        bool supportsChangeRequest = false;
    };

    // Detects NAT type using UDP Binding requests sent from an ephemeral port.
    // Implements the RFC 5780 mapping/filtering tests when the server provides
    // OTHER-ADDRESS (or RFC 3489 CHANGED-ADDRESS). Otherwise falls back to
    // comparing the mapping observed by two different servers, which can only
    // tell symmetric NAT apart from cone NAT.
    class StunNatTypeDetector final : public QObject
    {
        Q_OBJECT
        Q_DISABLE_COPY_MOVE(StunNatTypeDetector)

    public:
        explicit StunNatTypeDetector(QObject *parent = nullptr);
        ~StunNatTypeDetector() override;

        bool isRunning() const;
        void start(const QList<Stun::Endpoint> &servers);
        void abort();

    signals:
        void finished(const Net::NatDetectionResult &result);

    private:
        using ResponseHandler = std::function<void (const std::optional<Stun::Message> &response)>;

        void sendRequest(const Stun::Endpoint &target, bool changeIP, bool changePort, ResponseHandler handler);
        void retransmit();
        void readPendingDatagrams();

        void findPrimaryServer(int serverIndex);
        void onPrimaryServerFound(int serverIndex, const Stun::Message &response);
        void runFilteringTests(const Stun::Endpoint &mapped);
        void runSecondServerMappingTest(int serverIndex, const Stun::Endpoint &mapped);
        void finish(NatType type);

        QUdpSocket *m_socket = nullptr;
        QTimer *m_retransmitTimer = nullptr;
        QList<Stun::Endpoint> m_servers;
        NatDetectionResult m_result;
        Stun::Endpoint m_primaryServer;
        Stun::Endpoint m_otherAddress;

        // current transaction
        QByteArray m_transactionID;
        QByteArray m_request;
        Stun::Endpoint m_target;
        int m_attempt = 0;
        ResponseHandler m_handler;
    };
}

Q_DECLARE_METATYPE(Net::NatDetectionResult)
