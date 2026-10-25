from __future__ import annotations

import json

SCHEMA_VERSION = 'qloo4-m2-r02.v1'
_KEYS = {'schema_version', 'learner_objective', 'sequence', 'selected_qloo_evidence_ids', 'reason_for_inclusion', 'analogies', 'sources_needed', 'coverage', 'refusal_fallback'}


class PlannerValidationError(ValueError):
    pass


def _text(value, field, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise PlannerValidationError(f'{field} must be non-empty text.')
    return value.strip()


def _get(value, key, default=()):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def qloo_evidence_ids(evidence):
    if evidence is None:
        return []
    normalized = _get(evidence, 'normalized_evidence', evidence)
    found = []
    for key in ('entity_ids', 'tag_ids'):
        for value in _get(normalized, key, ()):
            if isinstance(value, str) and value.strip() and value.strip() not in found:
                found.append(value.strip())
    for row in _get(normalized, 'affinity_evidence', ()):
        value = row.get('entity_id', row.get('id', '')) if isinstance(row, dict) else row[2] if isinstance(row, (list, tuple)) and len(row) > 2 else ''
        if isinstance(value, str) and value.strip() and value.strip() not in found:
            found.append(value.strip())
    for resolution in _get(evidence, 'interest_resolutions', ()):
        # Search hits are candidates, not verified learner interests.
        # An ambiguous match must never become an evidence-backed plan.
        if _get(resolution, 'status', '') != 'resolved':
            continue
        for candidate in _get(resolution, 'candidates', ()):
            value = _get(candidate, 'identifier', _get(candidate, 'id', ''))
            if isinstance(value, str) and value.strip() and value.strip() not in found:
                found.append(value.strip())
    return found


def _check_list(value, field):
    if not isinstance(value, list):
        raise PlannerValidationError(f'{field} must be an array.')
    return value


def validate_plan(plan, qloo_evidence=None):
    if not isinstance(plan, dict) or set(plan) != _KEYS or plan['schema_version'] != SCHEMA_VERSION:
        raise PlannerValidationError('Plan does not match the versioned strict contract.')
    _text(plan['learner_objective'], 'learner_objective')
    selected = _check_list(plan['selected_qloo_evidence_ids'], 'selected_qloo_evidence_ids')
    if any(not isinstance(value, str) or not value.strip() for value in selected) or len(set(selected)) != len(selected):
        raise PlannerValidationError('Selected Qloo identifiers are invalid.')
    if qloo_evidence is not None and not set(selected).issubset(set(qloo_evidence_ids(qloo_evidence))):
        raise PlannerValidationError('Plan references a Qloo identifier not returned by Qloo.')
    for item in _check_list(plan['sequence'], 'sequence'):
        if not isinstance(item, dict) or set(item) != {'step', 'focus', 'source_claim_ids', 'qloo_evidence_ids'}:
            raise PlannerValidationError('Sequence item is invalid.')
        if not isinstance(item['step'], int) or isinstance(item['step'], bool) or item['step'] < 1:
            raise PlannerValidationError('Sequence step is invalid.')
        _text(item['focus'], 'sequence.focus')
        _check_list(item['source_claim_ids'], 'sequence.source_claim_ids')
        refs = _check_list(item['qloo_evidence_ids'], 'sequence.qloo_evidence_ids')
        if not set(refs).issubset(set(selected)):
            raise PlannerValidationError('Sequence contains an unselected Qloo identifier.')
    for item in _check_list(plan['reason_for_inclusion'], 'reason_for_inclusion'):
        if not isinstance(item, dict) or set(item) != {'evidence_id', 'reason'} or item['evidence_id'] not in selected:
            raise PlannerValidationError('Qloo inclusion reason is invalid.')
        _text(item['reason'], 'reason')
    for item in _check_list(plan['analogies'], 'analogies'):
        if not isinstance(item, dict) or set(item) != {'evidence_id', 'label', 'text'} or item['evidence_id'] not in selected or item['label'] != 'analogy':
            raise PlannerValidationError('Qloo-derived analogy is not identifier-bound.')
        _text(item['text'], 'analogy.text', 2000)
    _check_list(plan['sources_needed'], 'sources_needed')
    coverage = plan['coverage']
    if not isinstance(coverage, dict) or set(coverage) != {'source_claim_ids', 'unresolved', 'qloo_evidence_ids'} or coverage['qloo_evidence_ids'] != selected:
        raise PlannerValidationError('Coverage is invalid.')
    fallback = plan['refusal_fallback']
    if not isinstance(fallback, dict) or set(fallback) != {'status', 'reason', 'action'}:
        raise PlannerValidationError('Refusal/fallback is invalid.')
    if selected and fallback['status'] != 'ready':
        raise PlannerValidationError('Evidence-backed plan must be ready.')
    if not selected and (fallback['status'] != 'fallback' or not fallback['reason'] or not fallback['action'] or plan['reason_for_inclusion'] or plan['analogies']):
        raise PlannerValidationError('No-match plan must contain an explicit fallback and no invented example.')
    return plan


def build_lesson_plan(source_analysis, qloo_evidence, learner_objective):
    if not isinstance(source_analysis, dict) or source_analysis.get('schema_version') != 'qloo4-m2-r01.v1' or not isinstance(source_analysis.get('claims'), list):
        raise PlannerValidationError('source_analysis is not a supported source-analysis record.')
    objective = _text(learner_objective, 'learner_objective')
    claims = [claim for claim in source_analysis['claims'] if isinstance(claim, dict) and claim.get('assertable') is True and isinstance(claim.get('id'), str)]
    # Teaching order is limited to five steps; that limit is not a reason to
    # make later valid source claims unavailable to the writer. Bound the
    # per-request claim vocabulary separately to prevent unbounded prompts.
    allowed_claims = claims[:16]
    sequence = [{'step': index, 'focus': claim.get('text', objective), 'source_claim_ids': [claim['id']], 'qloo_evidence_ids': []} for index, claim in enumerate(claims[:5], 1)]
    if not sequence:
        sequence = [{'step': 1, 'focus': objective, 'source_claim_ids': [], 'qloo_evidence_ids': []}]
    identifiers = qloo_evidence_ids(qloo_evidence)[:3]
    if identifiers:
        sequence[0]['qloo_evidence_ids'] = identifiers[:2]
    plan = {
        'schema_version': SCHEMA_VERSION,
        'learner_objective': objective.strip(),
        'sequence': sequence,
        'selected_qloo_evidence_ids': identifiers,
        'reason_for_inclusion': [{'evidence_id': value, 'reason': 'Returned Qloo evidence is a labeled presentation bridge only.'} for value in identifiers],
        'analogies': [{'evidence_id': value, 'label': 'analogy', 'text': f'Use {value} only as a clearly labeled analogy; source claims remain authoritative.'} for value in identifiers],
        'sources_needed': [item.get('concept', item.get('text', '')) for item in source_analysis.get('unsupported_concepts', []) if isinstance(item, dict)],
        'coverage': {'source_claim_ids': [claim['id'] for claim in allowed_claims], 'unresolved': source_analysis.get('gaps', []), 'qloo_evidence_ids': identifiers},
        'refusal_fallback': {
            'status': 'ready' if identifiers else 'fallback',
            'reason': 'Returned Qloo evidence is available.' if identifiers else 'No usable Qloo match was returned; no Qloo-derived example will be invented.',
            'action': 'Writer may use only selected identifiers.' if identifiers else 'Writer uses source-grounded explanation with no Qloo-derived example.',
        },
    }
    return validate_plan(plan, qloo_evidence)


def parse_planner_json(raw, qloo_evidence=None):
    if not isinstance(raw, str):
        raise PlannerValidationError('Planner output must be a JSON string.')
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlannerValidationError('Planner output is not valid JSON.') from exc
    return validate_plan(value, qloo_evidence)


validate_lesson_plan = validate_plan
build_plan = build_lesson_plan
plan_lesson = build_lesson_plan
