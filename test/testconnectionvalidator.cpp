/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "account.h"
#include "creds/dummycredentials.h"
#include "gui/connectionvalidator.h"
#include "gui/localnetworkpermission.h"
#include "gui/proxyauthhandler.h"
#include "testhelper.h"

#include <QSignalSpy>
#include <QStandardPaths>
#include <QTest>

using namespace OCC;

namespace OCC {

class ConnectionValidatorTestAccess
{
public:
    static void setLocalNetworkPermissionDenied(ConnectionValidator &validator, bool denied)
    {
        validator._localNetworkPermissionCheck = [denied](const QUrl &, QObject *, std::function<void(bool)> callback) {
            callback(denied);
        };
    }

    static void reportTimeout(ConnectionValidator &validator, const QUrl &url)
    {
        validator.slotJobTimeout(url);
    }
};

}

class TestConnectionValidator : public QObject
{
    Q_OBJECT

    static AccountPtr createAccountWithProxy(const QString &user, const QString &password, const QString &url = QStringLiteral("https://cloud.example"))
    {
        const auto account = Account::create();
        account->setUrl(QUrl(url));
        account->setCredentials(new DummyCredentials);
        account->setProxySettings(QNetworkProxy::HttpProxy, QStringLiteral("proxy.example.com"), 8080, true, user, password);

        connect(account.data(), &Account::proxyAuthenticationRequired, ProxyAuthHandler::instance(), &ProxyAuthHandler::handleProxyAuthenticationRequired);
        connect(account.data(), &Account::networkProxySettingChanged, ProxyAuthHandler::instance(), &ProxyAuthHandler::resetProxyState);

        return account;
    }

private Q_SLOTS:
    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
    }

    void localNetworkPermissionFailureReplacesTimeout()
    {
        const auto account = Account::create();
        account->setUrl(QUrl(QStringLiteral("https://cloud.example")));
        const auto accountState = AccountStatePtr(new FakeAccountState(account));
        ConnectionValidator validator(accountState, {});
        ConnectionValidatorTestAccess::setLocalNetworkPermissionDenied(validator, true);
        QSignalSpy resultSpy(&validator, &ConnectionValidator::connectionResult);

        ConnectionValidatorTestAccess::reportTimeout(validator, account->url());

        QCOMPARE(resultSpy.count(), 1);
        const auto result = resultSpy.takeFirst();
        QCOMPARE(result.at(0).value<ConnectionValidator::Status>(), ConnectionValidator::Timeout);
        QCOMPARE(result.at(1).toStringList(), QStringList({LocalNetworkPermission::deniedError()}));
    }

    void proxyAuthenticationAppliesAccountCredentials()
    {
        ProxyAuthHandler::instance()->resetProxyState();
        const auto account = createAccountWithProxy(QStringLiteral("alice"), QStringLiteral("secret"));

        QCOMPARE(account->proxy().type(), QNetworkProxy::HttpProxy);
        QCOMPARE(account->proxy().hostName(), QStringLiteral("proxy.example.com"));
        QCOMPARE(account->proxy().port(), 8080);
        QCOMPARE(account->proxy().user(), QStringLiteral("alice"));
        QCOMPARE(account->proxy().password(), QStringLiteral("secret"));

        QAuthenticator authenticator;
        Q_EMIT account->proxyAuthenticationRequired(account->proxy(), &authenticator);

        QCOMPARE(authenticator.user(), QStringLiteral("alice"));
        QCOMPARE(authenticator.password(), QStringLiteral("secret"));
    }

    void proxyAuthenticationFailureBlocksUntilPasswordChange()
    {
        ProxyAuthHandler::instance()->resetProxyState();
        const auto account = createAccountWithProxy(QStringLiteral("alice"), QStringLiteral("wrongpassword"));

        // First attempt sends initial credentials
        QAuthenticator authenticator;
        Q_EMIT account->proxyAuthenticationRequired(account->proxy(), &authenticator);
        QCOMPARE(authenticator.user(), QStringLiteral("alice"));
        QCOMPARE(authenticator.password(), QStringLiteral("wrongpassword"));

        // Second attempt from same QNAM signals that the credentials failed (invalidated)
        QAuthenticator authenticator2;
        Q_EMIT account->proxyAuthenticationRequired(account->proxy(), &authenticator2);
        QVERIFY(authenticator2.user().isEmpty());

        // Updating the password resets state
        account->setProxyPassword(QStringLiteral("newsecret"));

        QAuthenticator authenticator3;
        Q_EMIT account->proxyAuthenticationRequired(account->proxy(), &authenticator3);
        QCOMPARE(authenticator3.user(), QStringLiteral("alice"));
        QCOMPARE(authenticator3.password(), QStringLiteral("newsecret"));
    }

    void proxyAuthenticationFailureDoesNotBlockOtherAccountsOnSameProxy()
    {
        ProxyAuthHandler::instance()->resetProxyState();
        const auto account1 = createAccountWithProxy(QStringLiteral("alice"), QStringLiteral("badpassword"), QStringLiteral("https://cloud1.example"));
        const auto account2 = createAccountWithProxy(QStringLiteral("bob"), QStringLiteral("goodpassword"), QStringLiteral("https://cloud2.example"));

        // Account 1 attempts and fails
        QAuthenticator auth1;
        Q_EMIT account1->proxyAuthenticationRequired(account1->proxy(), &auth1);
        QCOMPARE(auth1.user(), QStringLiteral("alice"));

        // Second attempt on account 1 invalidates credentials and blocks account 1
        QAuthenticator auth1_retry;
        Q_EMIT account1->proxyAuthenticationRequired(account1->proxy(), &auth1_retry);
        QVERIFY(auth1_retry.user().isEmpty());

        // Account 2 using the same proxy is NOT blocked and can authenticate successfully
        QAuthenticator auth2;
        Q_EMIT account2->proxyAuthenticationRequired(account2->proxy(), &auth2);
        QCOMPARE(auth2.user(), QStringLiteral("bob"));
        QCOMPARE(auth2.password(), QStringLiteral("goodpassword"));
    }

    void proxyAuthenticationBlockedAccountEvictedOnDestruction()
    {
        ProxyAuthHandler::instance()->resetProxyState();

        {
            const auto tempAccount = createAccountWithProxy(QStringLiteral("alice"), QStringLiteral("badpassword"));

            QAuthenticator auth1;
            Q_EMIT tempAccount->proxyAuthenticationRequired(tempAccount->proxy(), &auth1);

            QAuthenticator auth2;
            Q_EMIT tempAccount->proxyAuthenticationRequired(tempAccount->proxy(), &auth2);
            QVERIFY(auth2.user().isEmpty());
        }

        // A new account should NOT be blocked
        const auto newAccount = createAccountWithProxy(QStringLiteral("alice"), QStringLiteral("goodpassword"));

        QAuthenticator auth3;
        Q_EMIT newAccount->proxyAuthenticationRequired(newAccount->proxy(), &auth3);
        QCOMPARE(auth3.user(), QStringLiteral("alice"));
        QCOMPARE(auth3.password(), QStringLiteral("goodpassword"));
    }

    void manualProxyNotOverwrittenByConnectionValidator()
    {
        const auto account = createAccountWithProxy(QStringLiteral("alice"), QStringLiteral("secret"));

        const auto accountState = AccountStatePtr(new FakeAccountState(account));
        ConnectionValidator validator(accountState, {});
        validator.checkServerAndAuth();

        // Allow any background lookup to finish
        QTest::qWait(200);

        const auto currentProxy = account->networkAccessManager()->proxy();
        QCOMPARE(currentProxy.type(), QNetworkProxy::HttpProxy);
        QCOMPARE(currentProxy.hostName(), QStringLiteral("proxy.example.com"));
        QCOMPARE(currentProxy.port(), 8080);
    }
};

QTEST_MAIN(TestConnectionValidator)
#include "testconnectionvalidator.moc"
