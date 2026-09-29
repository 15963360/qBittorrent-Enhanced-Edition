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

#include <optional>

#include <QtTypes>
#include <QByteArray>
#include <QHostAddress>
#include <QString>

// Minimal STUN (RFC 5389 / RFC 8489, with RFC 3489 and RFC 5780 compatibility
// attributes) message codec. Only what is needed for Binding transactions
// (NAT type detection and public address discovery) is implemented.
namespace Net::Stun
{
    inline constexpr quint32 MAGIC_COOKIE = 0x2112A442;
    inline constexpr int HEADER_SIZE = 20;
    inline constexpr int TRANSACTION_ID_SIZE = 12;

    enum MessageType : quint16
    {
        BindingRequest = 0x0001,
        BindingSuccessResponse = 0x0101,
        BindingErrorResponse = 0x0111
    };

    enum AttributeType : quint16
    {
        MappedAddress = 0x0001,
        ChangeRequest = 0x0003,     // RFC 3489 / RFC 5780
        SourceAddress = 0x0004,     // RFC 3489
        ChangedAddress = 0x0005,    // RFC 3489
        ErrorCode = 0x0009,
        XorMappedAddress = 0x0020,
        XorMappedAddressOld = 0x8020,   // pre-RFC 5389 draft servers
        Software = 0x8022,
        ResponseOrigin = 0x802B,    // RFC 5780
        OtherAddress = 0x802C       // RFC 5780
    };

    struct Endpoint
    {
        QHostAddress address;
        quint16 port = 0;

        bool isValid() const;
        QString toString() const;

        friend bool operator==(const Endpoint &left, const Endpoint &right) = default;
    };

    struct Message
    {
        quint16 type = 0;
        QByteArray transactionID;
        bool hasMagicCookie = false;    // false for classic RFC 3489 servers

        Endpoint mappedAddress;
        Endpoint xorMappedAddress;
        Endpoint otherAddress;      // OTHER-ADDRESS or CHANGED-ADDRESS
        Endpoint responseOrigin;    // RESPONSE-ORIGIN or SOURCE-ADDRESS
        int errorCode = 0;
        QString errorReason;
        QString software;

        bool isSuccessResponse() const { return type == BindingSuccessResponse; }
        bool isErrorResponse() const { return type == BindingErrorResponse; }
        // XOR-MAPPED-ADDRESS takes precedence over MAPPED-ADDRESS
        Endpoint reflexiveAddress() const;
    };

    QByteArray generateTransactionID();

    // Builds a Binding request. CHANGE-REQUEST attribute is only added when
    // `changeIP` or `changePort` is set (RFC 5780 filtering tests).
    QByteArray buildBindingRequest(const QByteArray &transactionID, bool changeIP = false, bool changePort = false);

    // Returns full message size (header included) if `data` starts with
    // a plausible STUN header, 0 if more data is needed, -1 if it is not STUN.
    // Used for framing STUN over TCP (RFC 5389 section 7.2.2).
    int messageSize(const QByteArray &data);

    std::optional<Message> parseMessage(const QByteArray &data);
}
