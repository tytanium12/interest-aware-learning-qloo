from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable
from urllib import error, request

DEFAULT_BASE_URL = 'https://api.openai.com/v1'
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_OUTPUT_TOKENS = 16
DEFAULT_MAX_COST_USD = 0.01
DEFAULT_OUTPUT_USD_PER_MILLION_TOKENS = 0.60
HARD_MAX_OUTPUT_TOKENS = 64
HARD_MAX_REQUESTS = 2
LOW_COST_STRUCTURED_MODELS = ('gpt-4o-mini', 'gpt-4.1-mini', 'gpt-4.1-nano')
PROMPT = 'Return a JSON object whose only field is ok with the boolean value true.'


class PreflightError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


PreflightFailure = PreflightError


@dataclass(frozen=True)
class PreflightConfig:
    model: str | None = None
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    max_requests: int = HARD_MAX_REQUESTS
    max_cost_usd: float = DEFAULT_MAX_COST_USD
    output_usd_per_million_tokens: float = DEFAULT_OUTPUT_USD_PER_MILLION_TOKENS

    def __post_init__(self):
        if self.model is not None and (not self.model.strip() or '/' in self.model):
            raise PreflightError('configuration', 'Configured model is invalid.')
        if not self.base_url.startswith(('https://', 'http://')):
            raise PreflightError('configuration', 'Configured API base URL is invalid.')
        if not 0.5 <= float(self.timeout_seconds) <= 60.0:
            raise PreflightError('configuration', 'Timeout must be between 0.5 and 60 seconds.')
        if not 1 <= int(self.max_output_tokens) <= HARD_MAX_OUTPUT_TOKENS:
            raise PreflightError('configuration', 'Output-token limit exceeds the hard preflight cap.')
        if int(self.max_requests) != HARD_MAX_REQUESTS:
            raise PreflightError('configuration', 'Preflight permits exactly two bounded requests.')
        if float(self.max_cost_usd) <= 0 or float(self.output_usd_per_million_tokens) < 0:
            raise PreflightError('configuration', 'Cost guardrails must be non-negative and usable.')

    @classmethod
    def from_environment(cls, environ=None):
        values = os.environ if environ is None else environ
        def number(name, default, converter):
            raw = values.get(name)
            if raw is None or not str(raw).strip():
                return default
            try:
                return converter(raw)
            except (TypeError, ValueError):
                raise PreflightError('configuration', name + ' is invalid.')
        return cls(
            model=values.get('OPENAI_PREFLIGHT_MODEL') or values.get('OPENAI_MODEL') or None,
            base_url=values.get('OPENAI_API_BASE_URL') or DEFAULT_BASE_URL,
            timeout_seconds=number('OPENAI_PREFLIGHT_TIMEOUT_SECONDS', DEFAULT_TIMEOUT_SECONDS, float),
            max_output_tokens=number('OPENAI_PREFLIGHT_MAX_OUTPUT_TOKENS', DEFAULT_MAX_OUTPUT_TOKENS, int),
            max_requests=number('OPENAI_PREFLIGHT_MAX_REQUESTS', HARD_MAX_REQUESTS, int),
            max_cost_usd=number('OPENAI_PREFLIGHT_MAX_COST_USD', DEFAULT_MAX_COST_USD, float),
            output_usd_per_million_tokens=number('OPENAI_PREFLIGHT_OUTPUT_USD_PER_MILLION_TOKENS', DEFAULT_OUTPUT_USD_PER_MILLION_TOKENS, float),
        )


def _api_key(environ=None):
    values = os.environ if environ is None else environ
    direct = str(values.get('OPENAI_API_KEY') or '').strip()
    file_name = str(values.get('OPENAI_API_KEY_FILE') or '').strip()
    if direct and file_name:
        raise PreflightError('key', 'Configure an OpenAI key directly or through a file, not both.')
    if file_name:
        try:
            direct = Path(file_name).read_text(encoding='utf-8').strip()
        except OSError:
            raise PreflightError('key', 'Configured OpenAI key file is unavailable.')
    if not direct:
        raise PreflightError('key', 'OpenAI API key is not configured.')
    if len(direct) < 8 or any(character.isspace() for character in direct):
        raise PreflightError('key', 'Configured OpenAI API key is invalid.')
    return direct


def _http_error_code(status, details):
    error_data = details.get('error') if isinstance(details, dict) else None
    if isinstance(error_data, dict):
        text = ' '.join(str(error_data.get(name, '')) for name in ('code', 'type', 'message')).lower()
    else:
        text = str(error_data or '').lower()
    if status == 401:
        return 'key'
    if status == 403 or (status == 400 and 'model' in text):
        return 'model_access'
    if status in (402, 429) and any(term in text for term in ('quota', 'billing', 'payment', 'insufficient')):
        return 'quota_billing'
    if status == 429:
        return 'rate_limit'
    if status in (408, 504):
        return 'timeout'
    return 'provider_error'


def _request_json(url, api_key, method='GET', payload=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    body = None if payload is None else json.dumps(payload, separators=(',', ':')).encode('utf-8')
    headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + api_key}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    outgoing = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(outgoing, timeout=timeout) as response:
            raw = response.read(1024 * 1024)
    except error.HTTPError as exc:
        try:
            details = json.loads(exc.read(65536).decode('utf-8', errors='replace'))
        except Exception:
            details = {}
        raise PreflightError(_http_error_code(exc.code, details), 'OpenAI request was rejected.')
    except (socket.timeout, TimeoutError):
        raise PreflightError('timeout', 'OpenAI request timed out.')
    except error.URLError as exc:
        if isinstance(exc.reason, socket.timeout) or 'timed out' in str(exc.reason).lower():
            raise PreflightError('timeout', 'OpenAI request timed out.')
        raise PreflightError('network', 'OpenAI request could not be completed.')
    except OSError:
        raise PreflightError('network', 'OpenAI request could not be completed.')
    try:
        decoded = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PreflightError('malformed_response', 'OpenAI returned malformed JSON.')
    if not isinstance(decoded, dict):
        raise PreflightError('malformed_response', 'OpenAI returned an unexpected JSON shape.')
    return decoded


def _model_ids(payload):
    records = payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise PreflightError('malformed_response', 'OpenAI model listing is malformed.')
    identifiers = set()
    for record in records:
        if isinstance(record, dict) and isinstance(record.get('id'), str) and record['id'].strip():
            identifiers.add(record['id'])
    return identifiers


def _output_text(payload):
    if isinstance(payload.get('output_text'), str):
        return payload['output_text']
    output = payload.get('output')
    if not isinstance(output, list):
        return None
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get('content')
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and part.get('type') in ('output_text', 'text') and isinstance(part.get('text'), str):
                return part['text']
    return None


def _usage_summary(payload):
    usage = payload.get('usage')
    if not isinstance(usage, dict):
        return None
    summary = {}
    for name in ('input_tokens', 'output_tokens', 'total_tokens', 'prompt_tokens', 'completion_tokens'):
        value = usage.get(name)
        if isinstance(value, int) and value >= 0:
            summary[name] = value
    return summary or None


def _validate_generation(payload, selected_model):
    if not isinstance(payload, dict):
        raise PreflightError('malformed_response', 'OpenAI generation response is malformed.')
    status = payload.get('status')
    if status is not None and status != 'completed':
        raise PreflightError('malformed_response', 'OpenAI generation did not complete.')
    text = _output_text(payload)
    if not text or len(text) > 4096:
        raise PreflightError('malformed_response', 'OpenAI generation output is missing or oversized.')
    try:
        structured = json.loads(text)
    except json.JSONDecodeError:
        raise PreflightError('malformed_response', 'OpenAI generation output is not valid JSON.')
    if not isinstance(structured, dict) or structured.get('ok') is not True or set(structured) != {'ok'}:
        raise PreflightError('malformed_response', 'OpenAI generation output failed schema validation.')
    response_model = payload.get('model')
    if response_model is not None and not isinstance(response_model, str):
        raise PreflightError('malformed_response', 'OpenAI response model metadata is malformed.')
    return response_model, _usage_summary(payload)


def run_preflight(config=None, *, environ=None, request_json=None):
    values = os.environ if environ is None else environ
    settings = config or PreflightConfig.from_environment(values)
    key = _api_key(values)
    estimated_cost = settings.max_output_tokens * settings.output_usd_per_million_tokens / 1000000.0
    if estimated_cost > settings.max_cost_usd:
        raise PreflightError('quota_billing', 'Configured preflight cost guardrail is too low.')
    requester = request_json or _request_json
    base = settings.base_url.rstrip('/')
    models = requester(base + '/models', key, 'GET', None, settings.timeout_seconds)
    accessible = _model_ids(models)
    candidates = (settings.model,) if settings.model else LOW_COST_STRUCTURED_MODELS
    selected = next((candidate for candidate in candidates if candidate in accessible), None)
    if selected is None:
        raise PreflightError('model_access', 'No configured low-cost structured-output model is accessible.')
    payload = {
        'model': selected,
        'input': [{'role': 'user', 'content': [{'type': 'input_text', 'text': PROMPT}]}],
        'max_output_tokens': settings.max_output_tokens,
        'temperature': 0,
        'text': {'format': {'type': 'json_schema', 'name': 'preflight', 'strict': True, 'schema': {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok'], 'additionalProperties': False}}},
    }
    response = requester(base + '/responses', key, 'POST', payload, settings.timeout_seconds)
    response_model, usage = _validate_generation(response, selected)
    return {
        'status': 'PASS',
        'provider': 'openai',
        'model': selected,
        'response_model': response_model,
        'accessible_model_verified': True,
        'model_listing_request_count': 1,
        'generation_request_count': 1,
        'total_request_count': 2,
        'max_output_tokens': settings.max_output_tokens,
        'estimated_output_cost_usd': estimated_cost,
        'usage': usage,
        'prompt_kind': 'fixed-non-user-content',
        'response_payload_logged': False,
    }


QLOO_DEFAULT_BASE_URL = 'https://hackathon.api.qloo.com'
OPENAI_DEFAULT_BASE_URL = 'https://api.openai.com/v1'
HARD_MAX_RETRIES = 1
HARD_MAX_PROBES_PER_HOST = 1


class DependencyError(PreflightError):
    pass


@dataclass(frozen=True)
class DependencyConfig:
    qloo_base_url: str = QLOO_DEFAULT_BASE_URL
    openai_base_url: str = OPENAI_DEFAULT_BASE_URL
    timeout_seconds: float = 10.0
    max_retries: int = HARD_MAX_RETRIES
    max_probes_per_host: int = HARD_MAX_PROBES_PER_HOST

    def __post_init__(self):
        _validate_base_url(self.qloo_base_url, 'qloo')
        _validate_base_url(self.openai_base_url, 'openai')
        if not 0.5 <= float(self.timeout_seconds) <= 30.0:
            raise PreflightError('configuration', 'Timeout must be between 0.5 and 30 seconds.')
        if int(self.max_retries) < 0 or int(self.max_retries) > HARD_MAX_RETRIES:
            raise PreflightError('configuration', 'Retry count exceeds the hard cap.')
        if int(self.max_probes_per_host) != HARD_MAX_PROBES_PER_HOST:
            raise PreflightError('configuration', 'Exactly one minimal probe is permitted per host.')


def _validate_base_url(value, provider):
    from urllib.parse import urlsplit
    parsed = urlsplit(str(value).rstrip('/'))
    expected_host = 'hackathon.api.qloo.com' if provider == 'qloo' else 'api.openai.com'
    expected_path = '' if provider == 'qloo' else '/v1'
    if parsed.scheme != 'https' or parsed.hostname != expected_host or parsed.path.rstrip('/') != expected_path or parsed.query or parsed.fragment:
        raise PreflightError('endpoint_allowlist', 'Configured endpoint is outside the provider allowlist.')
    return str(value).rstrip('/')


def build_qloo_probe_request(base_url=QLOO_DEFAULT_BASE_URL):
    from urllib.parse import urlencode
    base = _validate_base_url(base_url, 'qloo')
    return base + '/search?' + urlencode({'query': 'preflight', 'take': '1'}), {'Accept': 'application/json', 'X-Api-Key': '[REDACTED]'}


def build_openai_probe_request(base_url=OPENAI_DEFAULT_BASE_URL):
    from urllib.parse import urlencode
    base = _validate_base_url(base_url, 'openai')
    return base + '/models?' + urlencode({'limit': '1'}), {'Accept': 'application/json', 'Authorization': 'Bearer [REDACTED]'}


def parse_probe_status(provider, status, payload):
    if status == 401 or status == 403:
        return 'authentication'
    if status == 429:
        return 'rate_limit'
    if status in (408, 504):
        return 'timeout'
    if isinstance(status, int) and status >= 500:
        return 'provider_error'
    if not isinstance(status, int) or not 200 <= status < 300:
        return 'request_error'
    expected_key = 'results' if provider == 'qloo' else 'data'
    if not isinstance(payload, dict) or not isinstance(payload.get(expected_key), list):
        return 'malformed_response'
    return 'ok'


def _safe_payload(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {'results': value}
    return {}


def _urllib_transport(url, headers, timeout):
    from urllib import error as urllib_error
    from urllib import request as urllib_request
    outgoing = urllib_request.Request(url, headers=headers, method='GET')
    try:
        with urllib_request.urlopen(outgoing, timeout=timeout) as response:
            raw = response.read(1024 * 1024)
            try:
                payload = json.loads(raw.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {}
            return int(response.status), _safe_payload(payload)
    except urllib_error.HTTPError as exc:
        try:
            payload = json.loads(exc.read(65536).decode('utf-8', errors='replace'))
        except Exception:
            payload = {}
        return int(exc.code), _safe_payload(payload)
    except (TimeoutError, OSError):
        raise


def probe_with_retry(provider, url, headers, timeout, transport, *, max_retries=HARD_MAX_RETRIES):
    attempts = 0
    last_code = 'network'
    for attempt in range(int(max_retries) + 1):
        attempts += 1
        try:
            status, payload = transport(url, headers, timeout)
            code = parse_probe_status(provider, status, payload)
            if code in {'timeout', 'rate_limit', 'provider_error'} and attempt < int(max_retries):
                continue
            return {'status': code, 'attempts': attempts}
        except (TimeoutError, OSError):
            last_code = 'timeout'
            if attempt < int(max_retries):
                continue
            return {'status': last_code, 'attempts': attempts}
        except Exception:
            last_code = 'network'
            if attempt < int(max_retries):
                continue
            return {'status': last_code, 'attempts': attempts}
    return {'status': last_code, 'attempts': attempts}


def _credential_presence(values, key_name, file_name):
    direct = bool(str(values.get(key_name) or '').strip())
    configured_file = str(values.get(file_name) or '').strip()
    file_present = bool(configured_file) and Path(configured_file).is_file()
    return {'configured': direct or file_present, 'source': 'environment' if direct else ('file' if file_present else 'absent')}


def _credential_value(values, key_name, file_name):
    direct = str(values.get(key_name) or '').strip()
    configured_file = str(values.get(file_name) or '').strip()
    if direct and configured_file:
        raise PreflightError('credential_configuration', 'Use one credential source per provider.')
    if direct:
        return direct
    if configured_file:
        return Path(configured_file).read_text(encoding='utf-8').strip()
    raise PreflightError('credential_presence', 'Required credential is unavailable.')


def run_offline_checks():
    qloo_url, qloo_headers = build_qloo_probe_request()
    openai_url, openai_headers = build_openai_probe_request()
    checks = {
        'authentication_setup': qloo_headers['X-Api-Key'] == '[REDACTED]' and openai_headers['Authorization'] == 'Bearer [REDACTED]',
        'endpoint_allowlist': qloo_url.startswith(QLOO_DEFAULT_BASE_URL) and openai_url.startswith(OPENAI_DEFAULT_BASE_URL),
        'request_construction': 'take=1' in qloo_url and openai_url.endswith('limit=1'),
        'status_error_parsing': all(parse_probe_status('qloo', status, payload) == expected for status, payload, expected in ((401, {}, 'authentication'), (429, {}, 'rate_limit'), (503, {}, 'provider_error'), (200, {'unexpected': []}, 'malformed_response'))),
        'bounded_retries': probe_with_retry('qloo', qloo_url, {}, 1.0, lambda url, headers, timeout: (200, {'results': []}), max_retries=1)['attempts'] == 1,
        'safe_evidence': '[REDACTED]' in qloo_headers['X-Api-Key'] and '[REDACTED]' in openai_headers['Authorization'],
    }
    if not all(checks.values()):
        raise PreflightError('offline_checks', 'Offline dependency preflight checks failed.')
    return {'status': 'PASS', 'checks': checks}


def run_dependency_preflight(config=None, *, environ=None, transport=None, authorized=False):
    values = os.environ if environ is None else environ
    settings = config or DependencyConfig()
    mock_result = run_offline_checks()
    presence = {
        'qloo': _credential_presence(values, 'QLOO_API_KEY', 'QLOO_API_KEY_FILE'),
        'openai': _credential_presence(values, 'OPENAI_API_KEY', 'OPENAI_API_KEY_FILE'),
    }
    result = {
        'schema': 'qloo-dependency-preflight-v1',
        'status': 'NOT_AUTHORIZED' if not authorized else 'NOT_RUN',
        'network_used': False,
        'real_probe': 'NOT_RUN',
        'mock_probe': 'MOCK',
        'mock_checks': mock_result['checks'],
        'credential_presence': presence,
        'probe_caps': {'max_probes_per_host': settings.max_probes_per_host, 'max_retries': settings.max_retries},
        'response_payload_logged': False,
    }
    if not authorized:
        return result
    if not presence['qloo']['configured'] or not presence['openai']['configured']:
        result['error_class'] = 'credential_presence'
        return result
    qloo_key = _credential_value(values, 'QLOO_API_KEY', 'QLOO_API_KEY_FILE')
    openai_key = _credential_value(values, 'OPENAI_API_KEY', 'OPENAI_API_KEY_FILE')
    qloo_url, _ = build_qloo_probe_request(settings.qloo_base_url)
    openai_url, _ = build_openai_probe_request(settings.openai_base_url)
    actual_transport = transport or _urllib_transport
    qloo_result = probe_with_retry('qloo', qloo_url, {'Accept': 'application/json', 'X-Api-Key': qloo_key}, settings.timeout_seconds, actual_transport, max_retries=settings.max_retries)
    openai_result = probe_with_retry('openai', openai_url, {'Accept': 'application/json', 'Authorization': 'Bearer ' + openai_key}, settings.timeout_seconds, actual_transport, max_retries=settings.max_retries)
    result['network_used'] = transport is None
    result['real_probe'] = 'REAL'
    result['probes'] = {'qloo': qloo_result, 'openai': openai_result}
    result['status'] = 'PASS' if qloo_result['status'] == 'ok' and openai_result['status'] == 'ok' else 'FAIL'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Bounded Qloo and OpenAI dependency preflight.')
    parser.add_argument('--live', action='store_true', help='Request the bounded real probes.')
    parser.add_argument('--qloo-base-url')
    parser.add_argument('--openai-base-url')
    parser.add_argument('--timeout-seconds', type=float)
    args = parser.parse_args(argv)
    try:
        values = os.environ
        config_values = {}
        if args.qloo_base_url is not None:
            config_values['qloo_base_url'] = args.qloo_base_url
        if args.openai_base_url is not None:
            config_values['openai_base_url'] = args.openai_base_url
        if args.timeout_seconds is not None:
            config_values['timeout_seconds'] = args.timeout_seconds
        settings = DependencyConfig(**config_values)
        approved = bool(args.live and values.get('QLOO_PREFLIGHT_APPROVED') == '1' and values.get('OPENAI_PREFLIGHT_APPROVED') == '1')
        result = run_dependency_preflight(settings, authorized=approved)
        print(json.dumps(result, separators=(',', ':')))
        return 0
    except PreflightError as exc:
        print(json.dumps({'status': 'FAIL', 'error_class': exc.code, 'message': str(exc)}, separators=(',', ':')))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
