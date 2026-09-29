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

#include <QByteArray>
#include <QHostAddress>
#include <QObject>
#include <QTest>

#include "base/global.h"
#include "base/net/stunmessage.h"

using namespace Net::Stun;

namespace
{
    // RFC 5769 section 2.1 transaction ID used by all sample messages
    const QByteArray TRANSACTION_ID = QByteArray::fromHex("b7e7a701bc34d686fa87dfae");

    // RFC 5769 section 2.2: sample IPv4 response
    const QByteArray SAMPLE_IPV4_RESPONSE = QByteArray::fromHex(
        "0101003c"
        "2112a442"
        "b7e7a701bc34d686fa87dfae"
        "8022000b"
        "74657374"
        "20766563"
        "746f7220"
        "00200008"
        "0001a147"
        "e112a643"
        "00080014"
        "2b91f599fd9e90c38c7489f92af9ba53f06be7d7"
        "80280004"
        "c07d4c96");

    // RFC 5769 section 2.3: sample IPv6 response
    const QByteArray SAMPLE_IPV6_RESPONSE = QByteArray::fromHex(
        "01010048"
        "2112a442"
        "b7e7a701bc34d686fa87dfae"
        "8022000b"
        "74657374"
        "20766563"
        "746f7220"
        "00200014"
        "0002a147"
        "0113a9faa5d3f179bc25f4b5bed2b9d9"
        "00080014"
        "a382954e4be67bf11784c97c8292c275bfe3ed41"
        "80280004"
        "c8fb0b4c");
}

class TestStunMessage final : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(TestStunMessage)

public:
    TestStunMessage() = default;

private slots:
    void testBuildBindingRequest() const
    {
        const QByteArray request = buildBindingRequest(TRANSACTION_ID);
        QCOMPARE(request.size(), HEADER_SIZE);
        QCOMPARE(request.left(8), QByteArray::fromHex("000100002112a442"));
        QCOMPARE(request.mid(8), TRANSACTION_ID);
        QCOMPARE(messageSize(request), HEADER_SIZE);

        const auto parsed = parseMessage(request);
        QVERIFY(parsed.has_value());
        QCOMPARE(parsed->type, quint16(BindingRequest));
        QVERIFY(parsed->hasMagicCookie);
        QCOMPARE(parsed->transactionID, TRANSACTION_ID);
    }

    void testBuildChangeRequest() const
    {
        const QByteArray both = buildBindingRequest(TRANSACTION_ID, true, true);
        QCOMPARE(both.size(), (HEADER_SIZE + 8));
        QCOMPARE(both.mid(2, 2), QByteArray::fromHex("0008"));
        QCOMPARE(both.mid(HEADER_SIZE), QByteArray::fromHex("0003000400000006"));

        const QByteArray portOnly = buildBindingRequest(TRANSACTION_ID, false, true);
        QCOMPARE(portOnly.mid(HEADER_SIZE), QByteArray::fromHex("0003000400000002"));
    }

    void testGenerateTransactionID() const
    {
        const QByteArray id1 = generateTransactionID();
        const QByteArray id2 = generateTransactionID();
        QCOMPARE(id1.size(), TRANSACTION_ID_SIZE);
        QCOMPARE(id2.size(), TRANSACTION_ID_SIZE);
        QVERIFY(id1 != id2);
    }

    void testParseRFC5769IPv4() const
    {
        const auto message = parseMessage(SAMPLE_IPV4_RESPONSE);
        QVERIFY(message.has_value());
        QVERIFY(message->isSuccessResponse());
        QCOMPARE(message->transactionID, TRANSACTION_ID);
        QCOMPARE(message->software, u"test vector"_s);
        QCOMPARE(message->xorMappedAddress.address, QHostAddress(u"192.0.2.1"_s));
        QCOMPARE(message->xorMappedAddress.port, 32853);
        QCOMPARE(message->reflexiveAddress().toString(), u"192.0.2.1:32853"_s);
    }

    void testParseRFC5769IPv6() const
    {
        const auto message = parseMessage(SAMPLE_IPV6_RESPONSE);
        QVERIFY(message.has_value());
        QVERIFY(message->isSuccessResponse());
        QCOMPARE(message->xorMappedAddress.address, QHostAddress(u"2001:db8:1234:5678:11:2233:4455:6677"_s));
        QCOMPARE(message->xorMappedAddress.port, 32853);
        QCOMPARE(message->reflexiveAddress().toString(), u"[2001:db8:1234:5678:11:2233:4455:6677]:32853"_s);
    }

    void testParseClassicAttributes() const
    {
        // RFC 3489 style response: MAPPED-ADDRESS, SOURCE-ADDRESS, CHANGED-ADDRESS
        QByteArray response = QByteArray::fromHex("01010024" "2112a442") + TRANSACTION_ID;
        response += QByteArray::fromHex("00010008" "0001" "1f90" "cb007101");   // 203.0.113.1:8080
        response += QByteArray::fromHex("00040008" "0001" "0d96" "c6336402");   // 198.51.100.2:3478
        response += QByteArray::fromHex("00050008" "0001" "0d97" "c6336403");   // 198.51.100.3:3479
        QCOMPARE(messageSize(response), response.size());

        const auto message = parseMessage(response);
        QVERIFY(message.has_value());
        QVERIFY(!message->xorMappedAddress.isValid());
        QCOMPARE(message->reflexiveAddress().toString(), u"203.0.113.1:8080"_s);
        QCOMPARE(message->responseOrigin.toString(), u"198.51.100.2:3478"_s);
        QCOMPARE(message->otherAddress.toString(), u"198.51.100.3:3479"_s);
    }

    void testXorMappedAddressPrecedence() const
    {
        // Both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS, some NATs rewrite the former
        QByteArray response = QByteArray::fromHex("01010018" "2112a442") + TRANSACTION_ID;
        response += QByteArray::fromHex("00010008" "0001" "1f90" "0a000001");   // 10.0.0.1:8080 (rewritten)
        response += QByteArray::fromHex("00200008" "0001" "a147" "e112a643");   // 192.0.2.1:32853
        const auto message = parseMessage(response);
        QVERIFY(message.has_value());
        QCOMPARE(message->reflexiveAddress().toString(), u"192.0.2.1:32853"_s);
    }

    void testParseErrorResponse() const
    {
        QByteArray response = QByteArray::fromHex("01110010" "2112a442") + TRANSACTION_ID;
        response += QByteArray::fromHex("0009000c" "00000414") + QByteArray("Unknown!");   // 420
        const auto message = parseMessage(response);
        QVERIFY(message.has_value());
        QVERIFY(message->isErrorResponse());
        QCOMPARE(message->errorCode, 420);
        QCOMPARE(message->errorReason, u"Unknown!"_s);
        QVERIFY(!message->reflexiveAddress().isValid());
    }

    void testInvalidMessages() const
    {
        QVERIFY(!parseMessage({}).has_value());
        QVERIFY(!parseMessage(SAMPLE_IPV4_RESPONSE.left(HEADER_SIZE - 1)).has_value());
        // truncated body
        QVERIFY(!parseMessage(SAMPLE_IPV4_RESPONSE.left(SAMPLE_IPV4_RESPONSE.size() - 4)).has_value());
        // attribute longer than message
        QByteArray bad = QByteArray::fromHex("01010008" "2112a442") + TRANSACTION_ID + QByteArray::fromHex("00200010" "0001a147");
        QVERIFY(!parseMessage(bad).has_value());
        // not STUN (first two bits set, e.g. TLS/HTTP)
        QVERIFY(!parseMessage(QByteArray(HEADER_SIZE, '\xff')).has_value());
        QCOMPARE(messageSize(QByteArray("HTTP/1.1 200 OK")), -1);
        QCOMPARE(messageSize(QByteArray::fromHex("0101")), 0);
    }
};

QTEST_APPLESS_MAIN(TestStunMessage)
#include "teststunmessage.moc"
