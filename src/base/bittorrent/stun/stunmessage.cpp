#include "stunmessage.h"

#include <QtEndian>
#include <QRandomGenerator>

namespace BitTorrent
{
    namespace STUN
    {
        TransactionID TransactionID::generate()
        {
            TransactionID id;
            QRandomGenerator::global()->fillRange(reinterpret_cast<quint32 *>(id.data), 3);
            return id;
        }

        bool TransactionID::operator==(const TransactionID &other) const
        {
            return (memcmp(data, other.data, sizeof(data)) == 0);
        }

        bool TransactionID::operator!=(const TransactionID &other) const
        {
            return !(*this == other);
        }

        QByteArray TransactionID::toByteArray() const
        {
            return QByteArray(reinterpret_cast<const char *>(data), sizeof(data));
        }

        TransactionID TransactionID::fromByteArray(const QByteArray &bytes)
        {
            TransactionID id {};
            const int len = qMin(static_cast<int>(sizeof(id.data)), bytes.size());
            if (len > 0)
                memcpy(id.data, bytes.constData(), len);
            return id;
        }

        Message::Message()
            : m_transactionID(TransactionID::generate())
        {
        }

        Message::Message(MessageClass msgClass, Method method, const TransactionID &transId)
            : m_class(msgClass)
            , m_method(method)
            , m_transactionID(transId)
        {
        }

        MessageClass Message::messageClass() const
        {
            return m_class;
        }

        Method Message::method() const
        {
            return m_method;
        }

        quint16 Message::messageType() const
        {
            const quint8 c0 = (static_cast<quint8>(m_class) & 0x01);
            const quint8 c1 = ((static_cast<quint8>(m_class) >> 1) & 0x01);
            const quint16 m = static_cast<quint16>(m_method);

            // RFC 5389 message type encoding:
            // bits 0..3: M0..M3
            // bit 4: C0
            // bits 5..7: M4..M6
            // bit 8: C1
            // bits 9..13: M7..M11
            return ((m & 0x000F) |
                   ((c0 << 4) & 0x0010) |
                   ((m & 0x0070) << 1) |
                   ((c1 << 8) & 0x0100) |
                   ((m & 0x0F80) << 2));
        }

        void Message::setMessageType(quint16 type)
        {
            const quint8 c0 = (type & 0x0010) >> 4;
            const quint8 c1 = (type & 0x0100) >> 8;
            m_class = static_cast<MessageClass>(c0 | (c1 << 1));

            const quint16 m = (type & 0x000F) |
                             ((type >> 1) & 0x0070) |
                             ((type >> 2) & 0x0F80);
            m_method = static_cast<Method>(m);
        }

        TransactionID Message::transactionID() const
        {
            return m_transactionID;
        }

        void Message::setTransactionID(const TransactionID &transId)
        {
            m_transactionID = transId;
        }

        void Message::setChangeRequest(bool changeIP, bool changePort)
        {
            m_hasChangeRequest = true;
            m_changeIP = changeIP;
            m_changePort = changePort;
        }

        bool Message::hasMappedAddress() const
        {
            return m_hasMappedAddress;
        }

        QHostAddress Message::mappedAddress() const
        {
            return m_mappedAddress;
        }

        quint16 Message::mappedPort() const
        {
            return m_mappedPort;
        }

        bool Message::hasOtherAddress() const
        {
            return m_hasOtherAddress;
        }

        QHostAddress Message::otherAddress() const
        {
            return m_otherAddress;
        }

        quint16 Message::otherPort() const
        {
            return m_otherPort;
        }

        bool Message::isSuccessResponse() const
        {
            return (m_class == MessageClass::SuccessResponse);
        }

        QByteArray Message::serialize() const
        {
            QByteArray attributes;

            if (m_hasChangeRequest)
            {
                // CHANGE-REQUEST attribute: Type (0x0003), Length (4), Flags (4 bytes)
                const quint16 attrType = qToBigEndian(static_cast<quint16>(AttributeType::ChangeRequest));
                const quint16 attrLen = qToBigEndian(static_cast<quint16>(4));
                quint32 flags = 0;
                if (m_changeIP)
                    flags |= 0x04;
                if (m_changePort)
                    flags |= 0x02;
                const quint32 flagsBe = qToBigEndian(flags);

                attributes.append(reinterpret_cast<const char *>(&attrType), 2);
                attributes.append(reinterpret_cast<const char *>(&attrLen), 2);
                attributes.append(reinterpret_cast<const char *>(&flagsBe), 4);
            }

            QByteArray packet;
            packet.reserve(HEADER_SIZE + attributes.size());

            const quint16 msgType = qToBigEndian(messageType());
            const quint16 msgLen = qToBigEndian(static_cast<quint16>(attributes.size()));
            const quint32 magic = qToBigEndian(MAGIC_COOKIE);

            packet.append(reinterpret_cast<const char *>(&msgType), 2);
            packet.append(reinterpret_cast<const char *>(&msgLen), 2);
            packet.append(reinterpret_cast<const char *>(&magic), 4);
            packet.append(reinterpret_cast<const char *>(m_transactionID.data), sizeof(m_transactionID.data));
            packet.append(attributes);

            return packet;
        }

        bool Message::parseAddressAttribute(const quint8 *val, quint16 len, bool xorMapped,
                                           const TransactionID &transId, QHostAddress &addr, quint16 &port)
        {
            if (len < 4)
                return false;

            const quint8 family = val[1];
            quint16 rawPort = qFromBigEndian<quint16>(val + 2);

            if (family == 0x01) // IPv4
            {
                if (len < 8)
                    return false;

                quint32 rawIp = qFromBigEndian<quint32>(val + 4);

                if (xorMapped)
                {
                    port = rawPort ^ static_cast<quint16>(MAGIC_COOKIE >> 16);
                    addr = QHostAddress(rawIp ^ MAGIC_COOKIE);
                }
                else
                {
                    port = rawPort;
                    addr = QHostAddress(rawIp);
                }

                return true;
            }

            if (family == 0x02) // IPv6
            {
                if (len < 20)
                    return false;

                if (xorMapped)
                {
                    port = rawPort ^ static_cast<quint16>(MAGIC_COOKIE >> 16);

                    quint8 xorBytes[16];
                    const quint32 magicBe = qToBigEndian(MAGIC_COOKIE);
                    memcpy(xorBytes, &magicBe, 4);
                    memcpy(xorBytes + 4, transId.data, 12);

                    quint8 ipv6Bytes[16];
                    for (int i = 0; i < 16; ++i)
                        ipv6Bytes[i] = val[4 + i] ^ xorBytes[i];

                    addr = QHostAddress(ipv6Bytes);
                }
                else
                {
                    port = rawPort;
                    addr = QHostAddress(val + 4);
                }

                return true;
            }

            return false;  // unsupported address family
        }

        bool Message::parse(const QByteArray &data, Message &outMessage)
        {
            if (data.size() < HEADER_SIZE)
                return false;

            const quint8 *ptr = reinterpret_cast<const quint8 *>(data.constData());

            const quint16 rawType = qFromBigEndian<quint16>(ptr);
            const quint16 msgLength = qFromBigEndian<quint16>(ptr + 2);
            const quint32 magicCookie = qFromBigEndian<quint32>(ptr + 4);

            // First two bits of STUN message must be 0
            if ((rawType & 0xC000) != 0)
                return false;

            // RFC 5389 requires Magic Cookie to match; RFC 3489 peers are still
            // tolerated, they simply never carry XOR-MAPPED-ADDRESS.
            const bool isRfc5389 = (magicCookie == MAGIC_COOKIE);

            outMessage.setMessageType(rawType);
            memcpy(outMessage.m_transactionID.data, ptr + 8, 12);

            // parse() fills a caller-supplied object, so start from a clean slate.
            outMessage.m_hasMappedAddress = false;
            outMessage.m_mappedAddress.clear();
            outMessage.m_mappedPort = 0;
            outMessage.m_hasOtherAddress = false;
            outMessage.m_otherAddress.clear();
            outMessage.m_otherPort = 0;

            if (data.size() < HEADER_SIZE + msgLength)
                return false;

            int offset = HEADER_SIZE;
            const int end = HEADER_SIZE + msgLength;

            while (offset + 4 <= end)
            {
                const quint16 attrType = qFromBigEndian<quint16>(ptr + offset);
                const quint16 attrLen = qFromBigEndian<quint16>(ptr + offset + 2);
                offset += 4;

                if (offset + attrLen > end)
                    break;

                const quint8 *attrVal = ptr + offset;

                switch (static_cast<AttributeType>(attrType))
                {
                case AttributeType::XorMappedAddress:
                    // Only meaningful once the magic cookie confirmed this is RFC 5389;
                    // decoding it as XOR otherwise would yield a garbage address.
                    if (isRfc5389
                        && parseAddressAttribute(attrVal, attrLen, true, outMessage.m_transactionID,
                                                 outMessage.m_mappedAddress, outMessage.m_mappedPort))
                    {
                        outMessage.m_hasMappedAddress = true;
                    }
                    break;

                case AttributeType::MappedAddress:
                    // XOR-MAPPED-ADDRESS wins when both attributes are present.
                    if (!outMessage.m_hasMappedAddress
                        && parseAddressAttribute(attrVal, attrLen, false, outMessage.m_transactionID,
                                                 outMessage.m_mappedAddress, outMessage.m_mappedPort))
                    {
                        outMessage.m_hasMappedAddress = true;
                    }
                    break;

                case AttributeType::OtherAddress:
                case AttributeType::ChangedAddress:
                    if (parseAddressAttribute(attrVal, attrLen, false, outMessage.m_transactionID,
                                              outMessage.m_otherAddress, outMessage.m_otherPort))
                    {
                        outMessage.m_hasOtherAddress = true;
                    }
                    break;

                default:
                    break;
                }

                // Attributes are padded to a multiple of 4 bytes
                offset += ((attrLen + 3) & ~3);
            }

            return true;
        }
    }
}
