#!/usr/bin/python
# vim:fileencoding=utf-8

import urllib2
import json

class ZabbixApi(object):
    """Zabbix APIを叩くクラス"""

    # タイムアウト時間(1分)
    TIMEOUT = 60

    class FailedError(Exception):
        """Zabbix APIで何かに失敗したときのエラー"""

        # Zabbix APIの形式に合わせたエラーメッセージのテンプレート
        ERROR_MESSAGE_TEMPLATE = '"{message}({code}): {data}"'

        def __init__(self, name, reason = None):
            """コンストラクタ

            @param(name)   失敗したメソッド名
            @param(reason) エラーレスポンス
            @return        自身のインスタンス
            """
            message = 'Failed to {0}.'.format(name)
            if reason is not None:
                if isinstance(reason, dict):
                    message = ' '.join([message, self.ERROR_MESSAGE_TEMPLATE.format(**reason)])
                else:
                    message = ' '.join([message, '"{0}"'.format(str(reason))])
            super(ZabbixApi.FailedError, self).__init__(message)

    class AuthenticationFailedError(FailedError):
        """Zabbixの認証トークン取得に失敗したときのエラー"""

        def __init__(self, reason = None):
            """コンストラクタ

            @param(reason) エラーレスポンス
            @return        自身のインスタンス
            """
            super(ZabbixApi.AuthenticationFailedError, self).__init__('authenticate', reason)

    class DeauthenticationFailedError(FailedError):
        """Zabbixの認証トークン破棄に失敗したときのエラー"""

        def __init__(self, reason = None):
            """コンストラクタ

            @param(reason) エラーレスポンス
            @return        自身のインスタンス
            """
            super(ZabbixApi.DeauthenticationFailedError, self).__init__('deauthenticate', reason)

    def __init__(self, host, user_name, password, request_id = 1, timeout = TIMEOUT):
        """コンストラクタ

        @param(host)       ZabbixサーバーのIPアドレス
        @param(user_name)  ユーザー名
        @param(password)   ユーザーパスワード
        @param(request_id) JSON-RPCの要求識別子(デフォルトは1)
        @param(timeout)    タイムアウト時間(デフォルトはZabbixApi.TIMEOUT)
        @return            自身のインスタンス
        """
        self.host = host
        self.user_name = user_name
        self.password = password
        self.request_id = request_id
        self.session_id = None
        self.timeout = timeout

    def __enter__(self):
        """with文に入るときに使用

        @return 自身のインスタンス
        """
        self.authenticate()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """with文から出るときに使用

        @return None
        """
        self.deauthenticate()

    def call(self, method, params = {}, through_authenticate = False):
        """Zabbix APIに手続きを要求する

        @param(method)               Zabbix APIのメソッド名
        @param(params)               Zabbix APIのメソッドパラメーター
        @param(through_authenticate) 事前の認証をパスするか(デフォルトはFalse)
        @return                      レスポンスのJSONを解析した辞書

        @test session_idがNoneかつthrough_authenticateがFalseのとき、authenticateが呼ばれること
        >>> from mock import MagicMock
        >>> urllib2.urlopen = MagicMock()
        >>> json.loads = MagicMock(return_value={})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.authenticate = MagicMock()
        >>> api.session_id is None
        True
        >>> api.call('method', {}, False)
        {}
        >>> api.authenticate.assert_called_once()

        @test through_authenticateがTrueのとき、authenticateが呼ばれないこと
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.authenticate = MagicMock()
        >>> api.call('method', {}, True)
        {}
        >>> api.authenticate.assert_not_called()

        @test session_idがNoneでないとき、authenticateが呼ばれないこと
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.authenticate = MagicMock()
        >>> api.session_id = 'session id'
        >>> api.call('method', {}, False)
        {}
        >>> api.authenticate.assert_not_called()
        """
        if not through_authenticate and self.session_id is None:
            self.authenticate()
        uri = 'http://{0}/zabbix/api_jsonrpc.php'.format(self.host)
        body = {
                'jsonrpc': '2.0',
                'method': method,
                'params': params,
                'auth': self.session_id,
                'id': self.request_id
                }
        data = json.dumps(body)
        headers = {'Content-Type': 'application/json-rpc'}
        request = urllib2.Request(uri, data, headers)
        response = urllib2.urlopen(request, timeout = self.timeout)
        response_json = json.loads(response.read())
        self.request_id = self.request_id + 1
        return response_json

    def authenticate(self):
        """ユーザー認証(ログイン)を行う

        @return Zabbix APIのセッションID

        @test response jsonにresultが含まれるときその内容をsession_idに保存し返却すること
        >>> from mock import MagicMock
        >>> urllib2.urlopen = MagicMock()
        >>> json.loads = MagicMock(return_value={'result': 'hoge'})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.authenticate()
        'hoge'
        >>> api.session_id
        'hoge'

        @test response jsonにerrorが含まれるときZabbixAuthenticationFailedErrorとなること
        >>> json.loads = MagicMock(return_value={'error': {'message': 'Hoge.', 'code': '114514', 'data': 'I am hoge.'}})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.authenticate()
        Traceback (most recent call last):
            ...
        AuthenticationFailedError: Failed to authenticate. "Hoge.(114514): I am hoge."

        @test 想定外のレスポンス内容のときZabbixAuthenticationFailedErrorとなること
        >>> json.loads = MagicMock(return_value={'hoge': 'huga'})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.authenticate()
        Traceback (most recent call last):
            ...
        AuthenticationFailedError: Failed to authenticate. "Unexpected response format. {"hoge": "huga"}"
        """
        response = self.call('user.login', {'user': self.user_name, 'password': self.password}, True)
        if 'result' in response:
            self.session_id = response['result']
            return response['result']
        elif 'error' in response:
            raise ZabbixApi.AuthenticationFailedError(response['error'])
        else:
            raise ZabbixApi.AuthenticationFailedError('Unexpected response format. {0}'.format(json.dumps(response)))

    def deauthenticate(self):
        """ユーザー認証の解除(ログアウト)を行う

        @return None

        @test レスポンスにerrorが含まれるときZabbixApiErrorとなること
        >>> from mock import MagicMock
        >>> urllib2.urlopen = MagicMock()
        >>> json.loads = MagicMock(return_value={'error': {'message': 'Hoge.', 'code': '114514', 'data': 'I am hoge.'}})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.deauthenticate()
        Traceback (most recent call last):
            ...
        DeauthenticationFailedError: Failed to deauthenticate. "Hoge.(114514): I am hoge."

        @test レスポンスにresultが含まれるときその内容がTrueであればsession_idを初期化すること
        >>> json.loads = MagicMock(return_value={'result': True})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.deauthenticate()
        >>> api.session_id

        @test レスポンスにresultが含まれるときその内容がFalseであればsession_idの値を変化させないこと
        >>> json.loads = MagicMock(return_value={'result': False})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.session_id = 'hoge'
        >>> api.deauthenticate()
        >>> api.session_id
        'hoge'

        @test 想定外のレスポンス内容のときZabbixUnexpectedResponseErrorとなること
        >>> json.loads = MagicMock(return_value={'hoge': 'huga'})
        >>> api = ZabbixApi('host', 'user', 'pass', 1)
        >>> api.deauthenticate()
        Traceback (most recent call last):
            ...
        DeauthenticationFailedError: Failed to deauthenticate. "Unexpected response format. {"hoge": "huga"}"
        """
        response = self.call('user.logout', [], True)
        if 'result' in response:
            if response['result']:
                self.session_id = None
        elif 'error' in response:
            raise ZabbixApi.DeauthenticationFailedError(response['error'])
        else:
            raise ZabbixApi.DeauthenticationFailedError('Unexpected response format. {0}'.format(json.dumps(response)))

if __name__ == '__main__':
    import sys

    if '-t' in sys.argv or '--test' in sys.argv:
        import doctest
        doctest.testmod()
    elif len(sys.argv) >= 5:
        host = sys.argv[1]
        user = sys.argv[2]
        password = sys.argv[3]
        method = sys.argv[4]
        params = json.loads(sys.argv[5]) if len(sys.argv) >= 6 else {}
        with ZabbixApi(host, user, password) as api:
            print(json.dumps(api.call(method, params)))
        sys.exit(0)
    else:
        print('Usage: zabbix_api.py [option] host user password method [params]')
        print('Option: -t, --test  execute doctest')
        sys.exit(1)

