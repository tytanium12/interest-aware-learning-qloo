from __future__ import annotations

import hashlib
import json
import re

SCHEMA_VERSION = 'qloo4-m2-r01.v1'
POLICY_VERSION = 'source-only-v1'
_MAX_SOURCE = 40000
_CHEMISTRY = re.compile(r'\b(?:acid(?:s)?|base(?:s)?|ph|proton(?:s)?|hydrogen\s+ion(?:s)?|hydroxide(?:s)?|neutraliz\w*|chemical(?:s)?|reaction(?:s)?|molecule(?:s)?|ion(?:s)?|buffer(?:s)?)\b', re.I)
_ARCHITECTURE = re.compile(r'\b(?:architecture|architectural|building|concrete|cement|steel|brick|mortar|construction|material|structure)\b', re.I)
_UNTRUSTED = re.compile(r'(?i)\b(?:ignore\s+(?:all\s+)?previous|system\s+message|developer\s+message|assistant\s+message|jailbreak|do\s+not\s+follow)\b')
_VOCABULARY = (
    r'\bacids?\b', r'\bbases?\b', r'\bpH\b', r'\bprotons?\b',
    r'\bhydrogen\s+ions?\b', r'\bhydroxides?\b', r'\bneutralization\b',
    r'\bbuffers?\b', r'\bequilibrium\b', r'\bconcrete\b', r'\bcement\b',
    r'\bsteel\b', r'\bbrick\b', r'\bmortar\b'
)

class SourceAnalysisError(ValueError):
    pass

def _source(text):
    if not isinstance(text, str):
        raise SourceAnalysisError('source_text must be text.')
    text = text.replace('\r\n', '\n').replace('\r', '\n').strip()
    if not text:
        raise SourceAnalysisError('source_text is required.')
    if len(text) > _MAX_SOURCE:
        raise SourceAnalysisError('source_text exceeds the configured limit.')
    return text

def _segments(text):
    segments = []
    for match in re.finditer(r'[^.!?\n]+(?:[.!?]+|(?=\n)|\Z)', text):
        raw = match.group(0)
        clean = raw.strip()
        if not clean:
            continue
        start = match.start() + len(raw) - len(raw.lstrip())
        segments.append({'text': clean, 'start': start, 'end': start + len(clean)})
    return segments

def _span(text, item):
    return {'start': item['start'], 'end': item['end'], 'anchor': f"source:{item['start']}-{item['end']}", 'text': text[item['start']:item['end']]}

def _refs(value):
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise SourceAnalysisError('supplemental_references must be a list or tuple.')
    refs = []
    for item in value:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str) and item[key].strip() for key in ('id', 'title', 'text')):
            raise SourceAnalysisError('Each supplemental reference needs id, title, and text.')
        refs.append({'id': item['id'].strip(), 'title': item['title'].strip(), 'text': item['text'].strip()})
    return refs

def _supported_by_reference(claim, refs):
    words = set(re.findall(r'[a-z]{4,}', claim.casefold()))
    for ref in refs:
        reference_text = ref['text'].casefold()
        if claim.casefold() in reference_text:
            return ref['id']
        reference_words = set(re.findall(r'[a-z]{4,}', reference_text))
        if words and len(words & reference_words) >= max(2, min(5, len(words))):
            return ref['id']
    return None

def _polarity(text):
    """Attribute acid/base proton verbs to their actual grammatical subjects.

    A source sentence can contain two compatible relationships, e.g.
    "acids donate protons, while bases accept protons". Looking for the
    words acid/base and donate/accept anywhere in that sentence falsely
    classified both as contradictory. Limit each subject to its own clause.
    This remains a deliberately conservative lexical conflict detector, not
    a semantic chemistry authority.
    """
    value = text.casefold()
    found = []
    subjects = list(re.finditer(r'\b(acids?|bases?)\b', value))
    for index, subject in enumerate(subjects):
        topic = 'acid-proton' if subject.group(1).startswith('acid') else 'base-proton'
        end = subjects[index + 1].start() if index + 1 < len(subjects) else len(value)
        clause = value[subject.end():end]
        if not re.search(r'\bprotons?\b', clause):
            continue
        if re.search(r'\bdonat\w*\b', clause):
            found.append((topic, 'donate'))
        if re.search(r'\baccept\w*\b', clause):
            found.append((topic, 'accept'))
    if re.search(r'\bph\b', value) and 'lower' in value:
        if re.search(r'more\s+acid|greater\s+acid', value):
            found.append(('ph-acidity', 'more-acidic'))
        if re.search(r'less\s+acid|more\s+basic', value):
            found.append(('ph-acidity', 'less-acidic'))
    return found

def _marked(items, words, text):
    return [{'text': item['text'], 'source_span': _span(text, item), 'basis': 'explicit_source_marker'} for item in items if any(word in item['text'].casefold() for word in words)]

def analyze_source(source_text, supplemental_references=None):
    source_text = _source(source_text)
    refs = _refs(supplemental_references)
    segments = _segments(source_text)
    untrusted = [
        {'text': item['text'], 'source_span': _span(source_text, item), 'reason': 'instruction-like text is treated as untrusted data'}
        for item in segments if _UNTRUSTED.search(item['text'])
    ]
    claims = []
    for item in segments:
        if _UNTRUSTED.search(item['text']):
            continue
        text = item['text']
        is_question = text.rstrip().endswith('?')
        restricted = bool(_CHEMISTRY.search(text) and _ARCHITECTURE.search(text))
        reference_id = _supported_by_reference(text, refs) if restricted else None
        if is_question:
            status, assertable = 'question', False
        elif restricted and reference_id is None:
            status, assertable = 'unsupported', False
        elif restricted:
            status, assertable = 'supplemental_supported', True
        else:
            status, assertable = 'source_only', True
        claims.append({
            'id': f'claim-{len(claims) + 1:03d}',
            'text': text,
            'source_span': _span(source_text, item),
            'support_status': status,
            'support_basis': 'explicitly supplied supplemental reference' if reference_id else ('question or request' if is_question else 'exact source span'),
            'supplemental_reference_ids': [reference_id] if reference_id else [],
            'assertable': assertable,
        })
    conflicts = []
    by_topic = {}
    for claim in claims:
        for topic, sign in _polarity(claim['text']):
            by_topic.setdefault(topic, {}).setdefault(sign, []).append(claim)
    for topic, signs in by_topic.items():
        if len(signs) > 1:
            ids = [claim['id'] for group in signs.values() for claim in group]
            conflicts.append({'topic': topic, 'claim_ids': ids, 'status': 'conflicting', 'resolution': 'preserve both source anchors; do not silently choose a fact'})
            for claim in claims:
                if claim['id'] in ids:
                    claim['support_status'] = 'conflicting'
                    claim['assertable'] = False
    vocabulary = []
    seen_terms = set()
    for pattern in _VOCABULARY:
        match = re.search(pattern, source_text, re.I)
        if match:
            term = match.group(0)
            if term.casefold() not in seen_terms:
                seen_terms.add(term.casefold())
                vocabulary.append({'term': term, 'source_span': {'start': match.start(), 'end': match.end(), 'anchor': f"source:{match.start()}-{match.end()}", 'text': match.group(0)}})
    explicit_objectives = _marked(segments, ('objective', 'learn', 'understand', 'explain', 'identify', 'compare'), source_text)
    objectives = explicit_objectives[:]
    if not objectives:
        objectives = [{'text': f"Explain the source-grounded claim: {claim['text']}", 'source_span': claim['source_span'], 'basis': 'derived_from_source_claim', 'claim_ids': [claim['id']]} for claim in claims if claim['assertable']]
    misconceptions = _marked(segments, ('misconception', 'myth', 'incorrect', 'wrong', 'not the same', 'does not', "doesn't", 'confus'), source_text)
    prerequisites = _marked(segments, ('prerequisite', 'requires', 'before', 'already know', 'prior knowledge'), source_text)
    unsupported = [
        {'claim_id': claim['id'], 'concept': claim['text'], 'source_span': claim['source_span'], 'reason': 'architecture/material chemistry requires an explicitly supplied supporting reference'}
        for claim in claims if claim['support_status'] == 'unsupported'
    ]
    gaps = [{'text': item['text'], 'source_span': _span(source_text, item), 'status': 'explicitly unresolved'} for item in segments if re.search(r'(?i)not enough|unknown|unclear|missing|need(?:s)? more|cannot determine', item['text'])]
    gaps.extend({'text': conflict['topic'], 'claim_ids': conflict['claim_ids'], 'status': 'conflicting source statements'} for conflict in conflicts)
    record = {
        'schema_version': SCHEMA_VERSION,
        'analysis_version': 1,
        'source_sha256': hashlib.sha256(source_text.encode('utf-8')).hexdigest(),
        'source_only_policy': {
            'version': POLICY_VERSION,
            'source_claims': 'Only exact source spans may be source-grounded claims.',
            'supplemental_references': 'Only explicitly supplied references may support external facts and are labeled supplemental.',
            'unsupported_concepts': 'Unsupported or conflicting concepts remain labeled and are not silently completed.',
            'qloo': 'Cultural affinity evidence is not a scientific reference.',
        },
        'claims': claims,
        'misconceptions': misconceptions,
        'prerequisites': prerequisites,
        'vocabulary': vocabulary,
        'learning_objectives': objectives,
        'gaps': gaps,
        'unsupported_concepts': unsupported,
        'conflicts': conflicts,
        'untrusted_text': untrusted,
        'supplemental_references': [{'id': ref['id'], 'title': ref['title'], 'sha256': hashlib.sha256(ref['text'].encode('utf-8')).hexdigest()} for ref in refs],
    }
    canonical = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    record['record_sha256'] = hashlib.sha256(canonical).hexdigest()
    return record

def validate_source_analysis(record, source_text=None):
    if not isinstance(record, dict) or record.get('schema_version') != SCHEMA_VERSION:
        return False
    source = _source(source_text) if source_text is not None else None
    for claim in record.get('claims', []):
        span = claim.get('source_span', {})
        if not isinstance(claim.get('text'), str) or span.get('text') != claim['text']:
            return False
        if source is not None and source[span.get('start', -1):span.get('end', -1)] != claim['text']:
            return False
        if claim.get('support_status') == 'unsupported' and claim.get('assertable') is not False:
            return False
    return True

def build_source_analysis_record(source_text, supplemental_references=None):
    return analyze_source(source_text, supplemental_references)

def analyze_educational_source(source_text, supplemental_references=None):
    return analyze_source(source_text, supplemental_references)
