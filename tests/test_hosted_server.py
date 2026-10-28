"""Offline hosted release gates: no external API calls, no dollars spent."""
import http.client
import io
import json
import os
import threading
import unittest
from dataclasses import replace
from unittest import mock

import app
import hosted_server as host


class FakeHTTPResponse:
    def __init__(self, value):
        self.value = value
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self, n=-1): return json.dumps(self.value).encode('utf-8')


class HostedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.settings = host.Settings(
            'https://example.onrender.com', True, 'judge-unique-secret-123', 'x' * 44,
            'https://fake-test.upstash.io', 't' * 40, 'ial:hackathon:2026:live:v1', 8)

    def test_live_config_defaults_off_and_missing_protections_rejected(self):
        self.assertFalse(host.Settings.read({}).enabled)
        with self.assertRaisesRegex(ValueError, 'HTTPS hosted origin'):
            host.Settings.read({'HOSTED_LIVE_ENABLED': '1'})
        with self.assertRaisesRegex(ValueError, 'HOSTED_LIVE_ENABLED'):
            host.Settings.read({'HOSTED_LIVE_ENABLED': 'true'})

    def test_contest_allowance_supports_200_and_rejects_excessive_values(self):
        settings = host.Settings.read({"HOSTED_MAX_GENERATIONS": "200"})
        self.assertEqual(settings.max_generations, 200)
        self.assertEqual(host.Settings.read({}).max_generations, 200)
        with self.assertRaisesRegex(ValueError, "Unsafe hosted quota"):
            host.Settings.read({"HOSTED_MAX_GENERATIONS": "501"})
        with self.assertRaisesRegex(ValueError, "Unsafe hosted quota"):
            host.Settings.read({"HOSTED_MAX_GENERATIONS": "0"})
        live_settings = host.Settings(
            self.settings.origin, True, self.settings.judge_code, self.settings.cookie_secret,
            self.settings.redis_url, self.settings.redis_token, self.settings.quota_key, 200)
        def fake_open(req, timeout):
            command = json.loads(req.data)
            self.assertEqual(command[-1], "200")
            return FakeHTTPResponse({"result": 200})
        self.assertTrue(host.reserve_generation(live_settings, opener=fake_open))
        self.assertFalse(host.reserve_generation(live_settings, opener=lambda req, timeout: FakeHTTPResponse({"result": -1})))

    def test_validity_and_expiration_of_signed_cookie(self):
        token = host.session_token(self.settings, 100000)
        self.assertTrue(host.authenticated(self.settings, host.COOKIE_NAME + '=' + token, now=100030))
        self.assertFalse(host.authenticated(self.settings, host.COOKIE_NAME + '=' + token, now=100000 + host.SESSION_LIFETIME + 1))
        self.assertFalse(host.authenticated(self.settings, host.COOKIE_NAME + '=' + token + 'BAD', now=100030))
        self.assertFalse(host.authenticated(self.settings, 'other=x', now=100030))

    def test_quota_atomic_evaluation_and_fail_closed(self):
        recorded = []
        def fake_open(req, timeout):
            self.assertEqual(timeout, 5)
            command = json.loads(req.data)
            self.assertEqual(command[0], 'EVAL')
            self.assertIn("redis.call('INCR'", command[1])
            self.assertEqual(command[3], self.settings.quota_key)
            recorded.append(command)
            return FakeHTTPResponse({'result': len(recorded)})
        self.assertTrue(host.reserve_generation(self.settings, opener=fake_open))
        self.assertTrue(host.reserve_generation(self.settings, opener=fake_open))
        self.assertEqual(len(recorded), 2)
        self.assertFalse(host.reserve_generation(self.settings, opener=lambda req, timeout: FakeHTTPResponse({'result': -1})))
        for value in ({'result': '1'}, {'result': 99}, {'error': 'boom'}):
            with self.assertRaises(RuntimeError):
                host.reserve_generation(self.settings, opener=lambda req, timeout: FakeHTTPResponse(value))
        with self.assertRaises(RuntimeError):
            host.reserve_generation(self.settings, opener=lambda req, timeout: (_ for _ in ()).throw(OSError('network down')))

    def _serve(self, settings):
        server = app.ThreadingHTTPServer(('127.0.0.1', 0), host.HostedHandler)
        server.hosted_settings = settings
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(timeout=5)))
        return server.server_port

    @staticmethod
    def _request(port, method, route, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            connection.request(method, route, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_health_and_disarmed_login_only(self):
        settings = host.Settings.read({})
        port = self._serve(settings)
        status, body, _ = self._request(port, 'GET', '/health')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['status'], 'ok')
        status, body, _ = self._request(port, 'GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'Judge access', body)
        self.assertNotIn(b'<script>', body)
        status, _, _ = self._request(port, 'POST', '/api/learn')
        self.assertEqual(status, 503)

    def test_unauthorized_request_refused_before_paid_calls(self):
        port = self._serve(self.settings)
        with mock.patch.object(host, 'reserve_generation', side_effect=AssertionError('quota must not be touched')):
            status, body, _ = self._request(port, 'POST', '/api/learn', b'{}', {'Content-Type': 'application/json'})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)['error']['code'], 'judge_access_required')


    def test_learner_ui_retains_references_without_exposing_diagnostics(self):
        page = app.HTML
        self.assertIn('Web research references', page)
        self.assertIn('lesson.append(refs)', page)
        self.assertIn('renderActions(lesson)', page)
        self.assertIn('Grounded in the pasted source material', page)
        self.assertIn('lesson-research-', page)
        self.assertIn('Learning studio', page)
        self.assertNotIn('Local learning studio', page)
        for internal_label in (
            'How this explanation was made', 'Qloo evidence and fallback details',
            'Provider trace', 'Pasted source facts and citations',
            'Personalization applied:', 'Verified Qloo entities/IDs',
        ):
            self.assertNotIn(internal_label, page)

    def test_login_origin_policy_and_cross_site_rejection(self):
        port = self._serve(self.settings)
        status, page, headers = self._request(port, 'GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'/judge-access', page)
        # HTML form navigation submits Origin:null under no-referrer.
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        login_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        body = 'passcode=judge-unique-secret-123'
        for unsafe_origin in ('null', 'https://attacker.example'):
            status, content, _ = self._request(
                port, 'POST', '/judge-access', body,
                dict(login_headers, Origin=unsafe_origin))
            self.assertEqual((status, content), (403, b'Access denied'))
        status, content, response_headers = self._request(
            port, 'POST', '/judge-access', body,
            dict(login_headers, Origin=self.settings.origin))
        self.assertEqual(status, 303, content)
        self.assertIn('HttpOnly', response_headers['Set-Cookie'])
        self.assertIn('Secure', response_headers['Set-Cookie'])
        self.assertEqual(response_headers['Location'], '/')

    def test_public_mode_requires_explicit_opt_in(self):
        self.assertFalse(host.Settings.read({}).public_demo)
        self.assertTrue(host.Settings.read({'HOSTED_PUBLIC_DEMO': '1'}).public_demo)
        with self.assertRaisesRegex(ValueError, 'HOSTED_PUBLIC_DEMO'):
            host.Settings.read({'HOSTED_PUBLIC_DEMO': 'yes'})
        env = {
            'HOSTED_LIVE_ENABLED': '1', 'HOSTED_PUBLIC_DEMO': '1',
            'HOSTED_ORIGIN': self.settings.origin,
            'UPSTASH_REDIS_REST_URL': self.settings.redis_url,
            'UPSTASH_REDIS_REST_TOKEN': self.settings.redis_token,
            'IAL_MODE': 'provider', 'IAL_TAVILY_ENRICHMENT': '1',
            'IAL_OPENAI_MAX_GENERATIONS': '1', 'IAL_AUDITED_BUDGET': '1',
            'IAL_OPENAI_MAX_OUTPUT_TOKENS': '6500',
            'TAVILY_API_KEY_FILE': '/mock/key',
        }
        with mock.patch.object(app, 'load_app_config'), mock.patch.object(host.Path, 'is_file', return_value=True):
            public = host.Settings.read(env)
            self.assertTrue(public.enabled and public.public_demo)
            self.assertEqual(public.max_generations, 200)
            with self.assertRaisesRegex(ValueError, 'authentication secrets'):
                host.Settings.read(dict(env, HOSTED_PUBLIC_DEMO='0'))

    def test_public_mode_open_studio_and_quota_fail_closed(self):
        public = replace(self.settings, public_demo=True)
        port = self._serve(public)
        status, page, headers = self._request(port, 'GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'Follow a question you already care about.', page)
        self.assertNotIn(b'/judge-access', page)
        self.assertNotIn('Set-Cookie', headers)
        status, _, _ = self._request(port, 'POST', '/judge-access',
            'passcode=judge-unique-secret-123',
            {'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 404)
        with mock.patch.object(host, 'reserve_generation', side_effect=AssertionError('invalid request')):
            status, _, _ = self._request(port, 'POST', '/api/learn',
                b'{}', {'Content-Type': 'application/json'})
        self.assertEqual(status, 400)
        payload = {
            'schema_version': app.HTTP_SCHEMA_VERSION, 'provider_mode': 'auto',
            'explicit_interests': ['gardening'],
            'pasted_educational_source_text': 'Sound is a mechanical wave.',
            'learning_request': 'Explain sound', 'cultural_context': 'classroom',
        }
        raw = json.dumps(payload).encode('utf-8')
        headers = {'Content-Type': 'application/json', 'Origin': public.origin}
        with mock.patch.object(host, 'reserve_generation', side_effect=AssertionError('origin mismatch')):
            status, _, _ = self._request(port, 'POST', '/api/learn', raw,
                dict(headers, Origin='https://attacker.example'))
        self.assertEqual(status, 403)
        with mock.patch.object(host, 'reserve_generation', return_value=False) as gate:
            status, data, _ = self._request(port, 'POST', '/api/learn', raw, headers)
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(data)['error']['code'], 'quota_exhausted')
        gate.assert_called_once()
        with mock.patch.object(host, 'reserve_generation', side_effect=RuntimeError('redis down')):
            status, data, _ = self._request(port, 'POST', '/api/learn', raw, headers)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(data)['error']['code'], 'quota_unavailable')
        cfg = app.AppConfig('provider', qloo_api_key='fake-key', openai_api_key='fake-key', openai_model='mock-model')
        with (mock.patch.object(host, 'reserve_generation', return_value=True) as quota,
              mock.patch.object(app, 'load_app_config', return_value=cfg),
              mock.patch.object(app, 'QlooCulturalIntelligenceProvider'),
              mock.patch.object(app, 'OpenAIResponsesLessonGenerationProvider'),
              mock.patch.object(app, 'run_learning_workflow', side_effect=RuntimeError('test-only stop')) as workflow):
            status, content, _ = self._request(port, 'POST', '/api/learn', raw, headers)
        quota.assert_called_once()
        workflow.assert_called_once()
        self.assertEqual(status, 500)
        self.assertNotIn(b'fake-key', content)

    def test_login_and_live_validation_and_quota_stop(self):
        port = self._serve(self.settings)
        status, _, _ = self._request(port, 'POST', '/judge-access', 'passcode=wrong', {'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 403)
        status, _, heads = self._request(port, 'POST', '/judge-access', 'passcode=judge-unique-secret-123', {'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 303)
        cookie = heads['Set-Cookie'].split(';', 1)[0]
        self.assertIn('HttpOnly', heads['Set-Cookie'])
        self.assertIn('Secure', heads['Set-Cookie'])
        status, page, _ = self._request(port, 'GET', '/', headers={'Cookie': cookie})
        self.assertEqual(status, 200)
        self.assertIn(b'/api/learn', page)
        hdr = {'Cookie': cookie, 'Content-Type': 'application/json', 'Origin': self.settings.origin}
        invalid = b'{"provider_mode":"provider"}'
        with mock.patch.object(host, 'reserve_generation', side_effect=AssertionError('invalid input')):
            status, _, _ = self._request(port, 'POST', '/api/learn', invalid, hdr)
        self.assertEqual(status, 400)
        payload = {
            'schema_version': app.HTTP_SCHEMA_VERSION, 'provider_mode': 'auto',
            'explicit_interests': ['gardening'], 'pasted_educational_source_text': 'Plants use energy from sunlight.',
            'learning_request': 'Explain energy', 'cultural_context': 'classroom',
        }
        body = json.dumps(payload).encode('utf-8')
        with mock.patch.object(host, 'reserve_generation', return_value=False) as gate:
            status, raw, _ = self._request(port, 'POST', '/api/learn', body, hdr)
        self.assertEqual(status, 429, raw)
        gate.assert_called_once()
        with mock.patch.object(host, 'reserve_generation', side_effect=RuntimeError('quota unavailable')):
            status, _, _ = self._request(port, 'POST', '/api/learn', body, hdr)
        self.assertEqual(status, 503)
        with mock.patch.object(host, 'reserve_generation', side_effect=AssertionError('wrong origin')):
            status, _, _ = self._request(port, 'POST', '/api/learn', body, dict(hdr, Origin='https://evil.example'))
        self.assertEqual(status, 403)

    def test_reserved_request_calls_existing_workflow(self):
        port = self._serve(self.settings)
        cookie = host.COOKIE_NAME + '=' + host.session_token(self.settings)
        payload = {
            'schema_version': app.HTTP_SCHEMA_VERSION, 'provider_mode': 'auto',
            'explicit_interests': ['gardening'], 'pasted_educational_source_text': 'Plants use energy from sunlight.',
            'learning_request': 'Explain energy', 'cultural_context': 'classroom',
        }
        raw = json.dumps(payload).encode('utf-8')
        class DummyProvider:
            def __init__(self, *args, **kwargs): pass
        # The existing HTTP Handler is exercised after reservation; mock its
        # external providers and config only. No real network is possible.
        cfg = app.AppConfig('provider', qloo_api_key='fake-key', openai_api_key='fake-key', openai_model='mock-model')
        with mock.patch.object(host, 'reserve_generation', return_value=True) as gate, \
             mock.patch.object(app, 'load_app_config', return_value=cfg), \
             mock.patch.object(app, 'QlooCulturalIntelligenceProvider', DummyProvider), \
             mock.patch.object(app, 'OpenAIResponsesLessonGenerationProvider', DummyProvider), \
             mock.patch.object(app, 'run_learning_workflow', side_effect=RuntimeError('no live transport should run')) as workflow:
            status, data, _ = self._request(port, 'POST', '/api/learn', raw, {'Cookie': cookie, 'Content-Type': 'application/json'})
        gate.assert_called_once()
        workflow.assert_called_once()
        self.assertEqual(status, 500)
        self.assertNotIn(b'fake-key', data)


if __name__ == '__main__':
    unittest.main()
