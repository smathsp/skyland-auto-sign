"""Offline regressions; no account credentials or real HTTP requests."""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
# Device ID initialization normally makes a request during skyland import.
device = ModuleType('SecuritySm')
device.get_d_id = lambda: 'test-device-id'
sys.modules['SecuritySm'] = device
with patch.dict(os.environ, {}, clear=True):
    import skyland
    import main
    import push
    from push.bark import push_bark


class OfflineTest(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        network = patch('requests.sessions.Session.request', side_effect=AssertionError('Unexpected HTTP request'))
        network.start()
        self.addCleanup(network.stop)
        sockets = patch('socket.socket.connect', side_effect=AssertionError('Unexpected socket connection'))
        sockets.start()
        self.addCleanup(sockets.stop)
        skyland.http_local.token = 'test-token'
        skyland.http_local.header = skyland.header.copy()


class SigningTests(OfflineTest):
    def test_signature_matches_payload_with_current_timestamp(self):
        with patch('skyland.time.time', return_value=1780000000.9):
            signature, header = skyland.generate_signature('/path', '{"x":1}')
        self.assertEqual(header['timestamp'], '1780000000')
        payload = '/path' + '{"x":1}' + '1780000000' + json.dumps(header, separators=(',', ':'))
        digest = hmac.new(b'test-token', payload.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(signature, hashlib.md5(digest.encode()).hexdigest())

    def test_bodyless_post_signature(self):
        with patch('skyland.generate_signature', return_value=('signature', {})) as sign:
            skyland.get_sign_header('https://example.com/path', 'post', None, {})
        sign.assert_called_once_with('/path', '')

    def test_arknights_success_and_failure(self):
        data = {'gameId': 1, 'uid': 'test-uid', 'gameName': '明日方舟'}
        for reply, expected in [
            ({'code': 0, 'data': {'awards': [{'resource': {'name': '奖励'}, 'count': 2}]}}, True),
            ({'code': 1, 'message': '失败'}, False),
        ]:
            with self.subTest(expected=expected), patch('requests.post', return_value=Mock(json=lambda: reply)) as post:
                success, logs = skyland.sign_for_arknights(data)
                self.assertEqual(success, expected)
                self.assertTrue(logs)
                self.assertEqual(post.call_args.kwargs['timeout'], (10, 30))

    def test_endfield_partial_failure_keeps_all_results(self):
        replies = [Mock(json=lambda: {'code': 1, 'message': '失败'}),
                   Mock(json=lambda: {'code': 0, 'data': {'resourceInfoMap': {'r': {'name': '奖励', 'count': 2}}, 'awardIds': [{'id': 'r'}]}})]
        data = {'gameName': '终末地', 'roles': [{'nickname': '甲'}, {'nickname': '乙'}]}
        with patch('skyland.do_sign_for_endfield', side_effect=replies):
            success, logs = skyland.sign_for_endfield(data)
        self.assertFalse(success)
        self.assertEqual(len(logs), 2)
        self.assertIn('奖励×2', logs[1])

    def test_endfield_without_roles_fails(self):
        self.assertFalse(skyland.sign_for_endfield({'gameName': '终末地'})[0])

    def test_role_failure_propagates_and_other_game_still_runs(self):
        with patch('skyland.get_binding_list', return_value=[{'appCode': 'arknights'}, {'appCode': 'endfield'}]), \
             patch('skyland.sign_for_arknights', return_value=(False, ['失败'])), \
             patch('skyland.sign_for_endfield', return_value=(True, ['成功'])):
            success, logs = skyland.do_sign({'token': 'fake', 'cred': 'fake'})
        self.assertFalse(success)
        self.assertEqual(logs, ['失败', '成功'])

    def test_no_bindings_fails(self):
        with patch('skyland.get_binding_list', return_value=[]):
            self.assertFalse(skyland.do_sign({'token': 'fake', 'cred': 'fake'})[0])

    def test_binding_error_preserves_local_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'TOKEN.txt'
            path.write_text('fake-token')
            with patch('skyland.token_save_name', str(path)), \
                 patch('requests.get', return_value=Mock(json=lambda: {'code': 1, 'message': '用户未登录'})):
                with self.assertRaises(RuntimeError):
                    skyland.get_binding_list()
            self.assertEqual(path.read_text(), 'fake-token')

    def test_account_exception_does_not_skip_other_accounts(self):
        with patch('skyland.init_token', return_value=['first', 'second']), \
             patch('skyland.get_cred_by_token', side_effect=[RuntimeError('登录失败'), {}]), \
             patch('skyland.do_sign', return_value=(True, ['第二个账号成功'])):
            success, logs = skyland.start()
        self.assertFalse(success)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[1], '第二个账号成功')


class AccountTests(OfflineTest):
    def test_full_browser_json_with_commas_or_pretty_printing(self):
        reply = {'code': 0, 'message': 'success', 'data': {'content': 'alpha'}}
        for value in [json.dumps(reply), json.dumps(reply, indent=2), json.dumps(reply) + '\nbeta']:
            with self.subTest(value=value), patch('skyland.token_env', value):
                self.assertEqual(skyland.read_from_env(), ['alpha', 'beta'] if value.endswith('beta') else ['alpha'])

    def test_mixed_separators_and_deduplication_after_parsing(self):
        value = ' alpha, beta\r\nalpha\n{"data":{"content":"beta"}}\n gamma '
        with patch('skyland.token_env', value):
            self.assertEqual(skyland.read_from_env(), ['alpha', 'beta', 'gamma'])

    def test_missing_ci_token_fails_without_prompting(self):
        os.environ['GITHUB_ACTIONS'] = 'true'
        with patch('skyland.token_env', None), patch('builtins.input') as prompt:
            success, logs = skyland.start()
        self.assertFalse(success)
        self.assertIn('TOKEN', logs[0])
        prompt.assert_not_called()

    def test_empty_tokens_fail(self):
        with patch('skyland.token_env', ' ,\n '):
            self.assertFalse(skyland.start()[0])

    def test_add_account_mode_remains_successful(self):
        with patch('skyland.current_type', 'add_account'), patch('skyland.init_token', return_value=[]):
            self.assertTrue(skyland.start()[0])

    def test_read_uses_requested_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'accounts.txt'
            path.write_text('first\nfirst\nsecond\n')
            with patch('skyland.token_save_name', str(path.parent / 'missing.txt')):
                self.assertEqual(skyland.read(str(path)), ['first', 'second'])

    def test_environment_has_priority_over_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / '__init__.py'
            module_path.with_name('config.ini').write_text('[PUSH_CONFIG]\nBARK_KEY=file-key\nBARK_SERVER=https://bark.example.com\n')
            os.environ['BARK_KEY'] = 'env-key'
            with patch.object(push, '__file__', str(module_path)):
                push.load_config_to_env()
            self.assertEqual(os.environ['BARK_KEY'], 'env-key')
            self.assertEqual(os.environ['BARK_SERVER'], 'https://bark.example.com')


class BarkTests(OfflineTest):
    def test_missing_key_skips_request(self):
        with patch('requests.post') as post:
            self.assertTrue(push_bark(['结果']))
        post.assert_not_called()

    def test_default_and_custom_server_preserve_unicode_and_newlines(self):
        for server, expected in [('', 'https://api.day.app/push'), ('https://bark.example.com/', 'https://bark.example.com/push'), ('http://localhost:8080/bark', 'http://localhost:8080/bark/push')]:
            with self.subTest(server=server), patch.dict(os.environ, {'BARK_KEY': 'fake-key', 'BARK_SERVER': server}), \
                 patch('requests.post', return_value=Mock(status_code=200, json=lambda: {'code': 200})) as post:
                self.assertTrue(push_bark(['明日方舟成功', '终末地失败']))
                self.assertEqual(post.call_args.args[0], expected)
                payload = post.call_args.kwargs['json']
                self.assertEqual(payload['device_key'], 'fake-key')
                self.assertEqual(payload['body'], '明日方舟成功\n终末地失败')
                self.assertEqual(payload['group'], '森空岛签到')
                self.assertEqual(post.call_args.kwargs['timeout'], (10, 30))
                self.assertFalse(post.call_args.kwargs['allow_redirects'])

    def test_http_and_application_errors_are_reported(self):
        os.environ['BARK_KEY'] = 'fake-key'
        for status, body in [(500, {'code': 200}), (200, {'code': 400}), (200, {})]:
            with self.subTest(status=status, body=body), patch('requests.post', return_value=Mock(status_code=status, json=lambda: body)), self.assertLogs(level='ERROR'):
                self.assertFalse(push_bark(['结果']))

    def test_timeout_or_invalid_json_does_not_leak_key_or_crash(self):
        os.environ['BARK_KEY'] = 'private-test-key'
        for response, exception in [(None, RuntimeError('URL contains private-test-key')), (Mock(status_code=200, json=Mock(side_effect=ValueError('private-test-key'))), None)]:
            with self.subTest(exception=exception), patch('requests.post', return_value=response, side_effect=exception), self.assertLogs(level='ERROR') as logs:
                self.assertFalse(push_bark(['结果']))
            self.assertNotIn('private-test-key', '\n'.join(logs.output))

    def test_invalid_server_is_rejected_without_http(self):
        os.environ['BARK_KEY'] = 'fake-key'
        for server in ['invalid', 'ftp://example.com', 'https://user:password@example.com', 'https://example.com?key=secret', 'https://example.com#fragment']:
            with self.subTest(server=server), patch.dict(os.environ, {'BARK_SERVER': server}), patch('requests.post') as post:
                self.assertFalse(push_bark(['结果']))
                post.assert_not_called()

    def test_empty_summary_uses_fallback(self):
        os.environ['BARK_KEY'] = 'fake-key'
        with patch('requests.post', return_value=Mock(status_code=200, json=lambda: {'code': 200})) as post:
            self.assertTrue(push_bark([]))
        self.assertTrue(post.call_args.kwargs['json']['body'])


class ExitTests(OfflineTest):
    def test_signin_failure_returns_nonzero_when_enabled(self):
        for enabled, expected in [('on', 1), ('off', 0), (None, 0)]:
            with self.subTest(enabled=enabled), patch.object(main, 'exit_when_fail_env', enabled), \
                 patch.object(main, 'config_logger'), patch.object(main, 'start', return_value=(False, ['失败'])), \
                 patch.object(main.push, 'push') as notify:
                self.assertEqual(main.main(), expected)
                notify.assert_called_once_with(['失败'])

    def test_notification_failure_preserves_successful_signin(self):
        with patch.object(main, 'exit_when_fail_env', 'on'), patch.object(main, 'config_logger'), \
             patch.object(main, 'start', return_value=(True, ['成功'])), patch.object(main.push, 'push', return_value=False):
            self.assertEqual(main.main(), 0)


if __name__ == '__main__':
    unittest.main()
