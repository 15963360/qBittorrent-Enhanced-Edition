#pragma once

#include <QByteArray>
#include <QHostAddress>
#include <QtGlobal>

namespace BitTorrent
{
    namespace STUN
    {
        constexpr quint32 MAGIC_COOKIE = 0x2112A442;
        constexpr int HEADER_SIZE = 20;

        enum class MessageClass : quint8
        {
            Request = 0,
            Indication = 1,
            SuccessResponse = 2,
            ErrorResponse = 3
        };

        enum class Method : quint16
        {
            Binding = 0x0001
        };

        enum class AttributeType : quint16
        {
            MappedAddress = 0x0001,
            ResponseAddress = 0x0002,
            ChangeRequest = 0x0003,
            SourceAddress = 0x0004,
            ChangedAddress = 0x0005,
            ErrorCode = 0x0009,
            XorMappedAddress = 0x0020,
            ResponseOrigin = 0x802B,
            OtherAddress = 0x802C
        };

        struct TransactionID
        {
            quint8 data[12];

            static TransactionID generate();
            bool operator==(const TransactionID &other) const;
            bool operator!=(const TransactionID &other) const;
            QByteArray toByteArray() const;
            static TransactionID fromByteArray(const QByteArray &bytes);
        };

        class Message
        {
        public:
            Message();
            Message(MessageClass msgClass, Method method, const TransactionID &transId);

            MessageClass messageClass() const;
            Method method() const;
            quint16 messageType() const;
            TransactionID transactionID() const;

            void setTransactionID(const TransactionID &transId);
            void setMessageType(quint16 type);

            // Attribute setters
            void setChangeRequest(bool changeIP, bool changePort);

            // Serialization & Deserialization
            QByteArray serialize() const;
            static bool parse(const QByteArray &data, Message &outMessage);

            // Extracted attributes
            bool hasMappedAddress() const;
            QHostAddress mappedAddress() const;
            quint16 mappedPort() const;

            bool hasOtherAddress() const;
            QHostAddress otherAddress() const;
            quint16 otherPort() const;

            bool isSuccessResponse() const;

        private:
            MessageClass m_class {MessageClass::Request};
            Method m_method {Method::Binding};
            TransactionID m_transactionID {};

            bool m_hasChangeRequest {false};
            bool m_changeIP {false};
            bool m_changePort {false};

            bool m_hasMappedAddress {false};
            QHostAddress m_mappedAddress;
            quint16 m_mappedPort {0};

            bool m_hasOtherAddress {false};
            QHostAddress m_otherAddress;
            quint16 m_otherPort {0};

            static bool parseAddressAttribute(const quint8 *val, quint16 len, bool xorMapped,
                                             const TransactionID &transId, QHostAddress &addr, quint16 &port);
        };
    }
}
