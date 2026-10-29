"""V42 conservative, source-neutral enrichment and personalization checks.

Heuristics are a rejection gate, not a proof of educational quality. Final
quality graduation requires independent comparison of complete lessons.
"""
from __future__ import annotations

import re

_CITE = re.compile(r'\[R[1-9][0-9]*\]')
_WORDS = re.compile(r'[^\W_]+', re.UNICODE)
_STOP = frozenset('''a about above after again against all also an and any are as at be
because been before between both but by can could did do does during each either
for from had has have having how i if in into is it its just may might more most
much must my new no not of on once one only or other our out over per same she
should so some such than that the their them then there these they this those
through to too under until up use used using very was we were what when where
which while who why will with within would you your not yet further different
research source sources study results report article says notes describes example
examples explains explanation consider compared comparing assume given question
questions true false information material lesson learners learning learner'''.split())
def _normalize_token(token):
    """Conservative word-form matching, including the two-letter term pH."""
    word = token.casefold()
    if len(word) > 5 and word.endswith('ies'):
        return word[:-3] + 'y'
    if len(word) > 6 and word.endswith('ing'):
        return word[:-3]
    if len(word) > 5 and word.endswith('ers'):
        return word[:-1]
    if len(word) > 4 and word.endswith('s') and not word.endswith('ss'):
        return word[:-1]
    return word


def _tokens(text):
    return {_normalize_token(w) for w in _WORDS.findall(text or '')
            if len(w) >= 3 or w.casefold() == 'ph'}


def _interesting(text):
    return {w for w in _tokens(text) if len(w) >= 5 and w not in _STOP}


def explanatory_blocks(lesson):
    """One iteration contract for inline sections and separate explanatory examples."""
    if not isinstance(lesson, dict):
        return
    for section in lesson.get('sections', ()):
        if isinstance(section, dict) and isinstance(section.get('explanation'), str):
            yield {'title': section.get('heading', ''), 'context': '',
                   'explanation': section['explanation'],
                   'source_claim_ids': section.get('source_claim_ids', ())}
    for example in lesson.get('examples', ()):
        if isinstance(example, dict) and isinstance(example.get('explanation'), str):
            yield example


def _example_text(example):
    return ' '.join(str(example.get(field, '')) for field in ('context','explanation'))


def _support_words(text):
    # Short domain concepts such as pH are informative; the source text, not a
    # hard-coded chemistry vocabulary, determines what counts as course content.
    return {w for w in _tokens(text) if w not in _STOP}


def _get_excerpt(source):
    return source.get('snippet') or source.get('excerpt') or ''


def _source_novel_words(source, educational_source):
    excerpt = _get_excerpt(source)
    # Facts must be genuinely outside the pasted instructional source.
    return _interesting(excerpt) - _tokens(educational_source)


def _supported_research_example(example, source, educational_source):
    if not isinstance(example, dict) or not isinstance(source, dict):
        return False
    identifier = source.get('id')
    if not isinstance(identifier, str) or not re.fullmatch(r'R[1-9][0-9]*', identifier):
        return False
    combined = _example_text(example)
    explanation = example.get('explanation', '')
    if not isinstance(explanation, str) or len(_tokens(explanation)) < 8:
        return False
    if f'[{identifier}]' not in combined:
        return False
    novel = _source_novel_words(source, educational_source)
    if len(novel) < 2:
        return False
    explanation_words = _tokens(explanation)
    example_words = _tokens(combined)
    # Two distinct facts-related terms from the retrieved excerpt and at least
    # one in the explanation. A bracketed citation alone cannot satisfy this.
    if len(novel & example_words) < 2 or not (novel & explanation_words):
        return False
    if not (explanation_words & _support_words(educational_source)):
        return False
    # Terms from both the research excerpt and the educational source must
    # appear in actual explanatory prose. No arbitrary connective-word list:
    # valid explanations may communicate causality without those exact words.
    return True


def substantively_uses_research(lesson, research_sources, educational_source):
    """Reject source citation without a fact-bearing interest-aware explanation.

    Assumes the existing Tavily URL/citation validator already passed.
    """
    if not research_sources:
        return True
    if not isinstance(lesson, dict) or not isinstance(research_sources, (tuple, list)):
        return False
    for example in explanatory_blocks(lesson):
        for source in research_sources:
            if _supported_research_example(example, source, educational_source):
                return True
    return False


def _interest_forms(interests):
    forms = set()
    for item in interests:
        if not isinstance(item, str):
            continue
        for word in _interesting(item):
            forms.add(word)
            for suffix in ('ing','es','s'):
                if word.endswith(suffix) and len(word) > len(suffix) + 3:
                    forms.add(word[:-len(suffix)])
    return forms


def reconcile_personalization(lesson, interests, research_sources=(), educational_source=''):
    """Align flags with actual interest-specific prose, not empty example arrays.

    Never upgrade a model-declared negative claim; deterministic checks can only
    disqualify unsupported positive flags. Explicit example flags are corrected
    independently of natural section-level personalization.
    """
    forms = _interest_forms(interests)
    blocks = list(explanatory_blocks(lesson))
    valid_research = substantively_uses_research(lesson, research_sources, educational_source)

    def concrete(block):
        content = (str(block.get('context', '')) + ' ' + str(block.get('explanation', ''))).casefold()
        direct_interest = any(re.search(r'(?<!\w)' + re.escape(form) + r'\w*', content) for form in forms)
        related_research = valid_research and any(
            _supported_research_example(block, source, educational_source)
            for source in research_sources
        )
        return direct_interest or related_research

    for ex in lesson.get('examples', ()):
        if isinstance(ex, dict) and ex.get('personalized') is True and not concrete(ex):
            ex['personalized'] = False
    # A section is as legitimate as an example; the model still has to claim
    # personalization explicitly for us to retain the positive aggregate flag.
    if lesson.get('personalization_applied') is True and not any(concrete(block) for block in blocks):
        lesson['personalization_applied'] = False
        lesson['personalization_note'] = (
            'No demonstrably interest-specific explanation was used; '
            'personalization was not applied.'
        )
    return lesson
