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

#include "stunmessage.h"

#include <cstring>

#include <QtEndian>

#include "base/global.h"
#include "base/utils/random.h"

using namespace Net::Stun;

namespace
{
    constexpr quint16 FAMILY_IPV4 = 0x01;
    constexpr quint16 FAMILY_IPV6 = 0x02;

    // CHANGE-REQUEST flags
    constexpr quint32 CHANGE_IP_FLAG = 0x04;
    constexpr quint32 CHANGE_PORT_FLAG = 0x02;

    void appendUInt16(QByteArray &buffer, const quint16 value)
    {
        char bytes[2];
        qToBigEndian(value, bytes);
        buffer.append(bytes, sizeof(bytes));
    }

    void appendUInt32(QByteArray &buffer, const quint32 value)
    {
        char bytes[4];
        qToBigEndian(value, bytes);
        buffer.append(bytes, sizeof(bytes));
    }

    quint16 readUInt16(const char *data)
    {
        return qFromBigEndian<quint16>(data);
    }

    quint32 readUInt32(const char *data)
    {
        return qFromBigEndian<quint32>(data);
    }

    // Parses (XOR-)MAPPED-ADDRESS style attribute value
    Endpoint parseAddress(const QByteArray &value, const bool isXored, const QByteArray &transactionID)
    {
        if (value.size() < 8)
            return {};

        const char *data = value.constData();
        const quint16 family = static_cast<quint8>(data[1]);
        quint16 port = readUInt16(data + 2);
        if (isXored)
            port ^= static_cast<quint16>(MAGIC_COOKIE >> 16);

        if (family == FAMILY_IPV4)
        {
            quint32 ip = readUInt32(data + 4);
            if (isXored)
                ip ^= MAGIC_COOKIE;
            return {QHostAddress(ip), port};
        }

        if ((family == FAMILY_IPV6) && (value.size() >= 20))
        {
            Q_IPV6ADDR ip;
            std::memcpy(ip.c, data + 4, 16);
            if (isXored)
            {
                char mask[16];
                qToBigEndian(MAGIC_COOKIE, mask);
                std::memcpy(mask + 4, transactionID.constData(), TRANSACTION_ID_SIZE);
                for (int i = 0; i < 16; ++i)
                    ip.c[i] = static_cast<quint8>(ip.c[i] ^ static_cast<quint8>(mask[i]));
            }
            return {QHostAddress(ip), port};
        }

        return {};
    }
}

bool Endpoint::isValid() const
{
    return !address.isNull() && (port != 0);
}

QString Endpoint::toString() const
{
    if (!isValid())
        return {};

    if (address.protocol() == QAbstractSocket::IPv6Protocol)
        return u"[%1]:%2"_s.arg(address.toString(), QString::number(port));
    return u"%1:%2"_s.arg(address.toString(), QString::number(port));
}

Endpoint Message::reflexiveAddress() const
{
    return xorMappedAddress.isValid() ? xorMappedAddress : mappedAddress;
}

QByteArray Net::Stun::generateTransactionID()
{
    QByteArray id;
    id.reserve(TRANSACTION_ID_SIZE);
    for (int i = 0; i < (TRANSACTION_ID_SIZE / 4); ++i)
        appendUInt32(id, Utils::Random::rand());
    return id;
}

QByteArray Net::Stun::buildBindingRequest(const QByteArray &transactionID, const bool changeIP, const bool changePort)
{
    Q_ASSERT(transactionID.size() == TRANSACTION_ID_SIZE);

    const bool hasChangeRequest = changeIP || changePort;
    const quint16 bodyLength = hasChangeRequest ? 8 : 0;

    QByteArray message;
    message.reserve(HEADER_SIZE + bodyLength);
    appendUInt16(message, BindingRequest);
    appendUInt16(message, bodyLength);
    appendUInt32(message, MAGIC_COOKIE);
    message.append(transactionID.left(TRANSACTION_ID_SIZE));

    if (hasChangeRequest)
    {
        appendUInt16(message, ChangeRequest);
        appendUInt16(message, 4);
        appendUInt32(message, (changeIP ? CHANGE_IP_FLAG : 0) | (changePort ? CHANGE_PORT_FLAG : 0));
    }

    return message;
}

int Net::Stun::messageSize(const QByteArray &data)
{
    if (data.size() < 4)
        return 0;

    // The most significant 2 bits of every STUN message are zeroes
    if ((static_cast<quint8>(data[0]) & 0xC0) != 0)
        return -1;

    const quint16 length = readUInt16(data.constData() + 2);
    if ((length % 4) != 0)
        return -1;

    return HEADER_SIZE + length;
}

std::optional<Message> Net::Stun::parseMessage(const QByteArray &data)
{
    if (data.size() < HEADER_SIZE)
        return std::nullopt;

    const char *raw = data.constData();
    const quint16 type = readUInt16(raw);
    const quint16 length = readUInt16(raw + 2);
    if (((type & 0xC000) != 0) || ((length % 4) != 0) || ((HEADER_SIZE + length) > data.size()))
        return std::nullopt;

    Message message;
    message.type = type;
    message.hasMagicCookie = (readUInt32(raw + 4) == MAGIC_COOKIE);
    message.transactionID = data.mid(8, TRANSACTION_ID_SIZE);

    int offset = HEADER_SIZE;
    const int end = HEADER_SIZE + length;
    while ((offset + 4) <= end)
    {
        const quint16 attrType = readUInt16(raw + offset);
        const quint16 attrLength = readUInt16(raw + offset + 2);
        offset += 4;
        if ((offset + attrLength) > end)
            return std::nullopt;

        const QByteArray value = data.mid(offset, attrLength);
        switch (attrType)
        {
        case MappedAddress:
            message.mappedAddress = parseAddress(value, false, message.transactionID);
            break;
        case XorMappedAddress:
        case XorMappedAddressOld:
            if (message.hasMagicCookie)
                message.xorMappedAddress = parseAddress(value, true, message.transactionID);
            break;
        case OtherAddress:
        case ChangedAddress:
            if (!message.otherAddress.isValid())
                message.otherAddress = parseAddress(value, false, message.transactionID);
            break;
        case ResponseOrigin:
        case SourceAddress:
            if (!message.responseOrigin.isValid())
                message.responseOrigin = parseAddress(value, false, message.transactionID);
            break;
        case ErrorCode:
            if (value.size() >= 4)
            {
                message.errorCode = ((static_cast<quint8>(value[2]) & 0x07) * 100) + static_cast<quint8>(value[3]);
                message.errorReason = QString::fromUtf8(value.mid(4));
            }
            break;
        case Software:
            message.software = QString::fromUtf8(value);
            break;
        default:
            break;
        }

        // attributes are padded to 4 bytes boundary
        offset += (attrLength + 3) & ~3;
    }

    return message;
}
