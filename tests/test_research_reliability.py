"""No-network regression tests for Qloo research-acceptance reliability."""
import json
import os
import unittest
from unittest.mock import patch

import app
import lesson_writer
from research_teaching_quality import substantively_uses_research
from tavily_enrichment import verify_research_citations

SOURCE = ('An acid donates a proton to another substance. In water, a proton may transfer. '
          'The pH scale describes acidity: lower pH corresponds to greater acidity. '
          'A base can accept a proton.')
RESEARCH = ({'id': 'R1', 'title': 'University extension guidance',
             'url': 'https://extension.example.edu/soil',
             'snippet': 'Gardeners grow blueberries in acidic soil. Soil testing guides planting '
                        'decisions; nutrient availability varies among vegetables.'},)

class ResearchReliabilityTests(unittest.TestCase):
    def test_accurate_paraphrase_and_correct_citation_pass(self):
        explanation = ('The extension service explains that gardeners use soil tests to select '
                       'plots for blueberry bushes [R1]. A lower pH value means more acidity; '
                       'this measurement matters when selecting a growing location.')
        lesson = {'sections': [{'heading':'Growing conditions', 'explanation': explanation}]}
        self.assertTrue(verify_research_citations(lesson, RESEARCH))
        self.assertTrue(substantively_uses_research(lesson, RESEARCH, SOURCE))

    def test_missing_or_fabricated_references_stay_rejected(self):
        lesson = {'sections':[{'heading':'Care', 'explanation':'Soil tests guide gardening and lower pH means acidity.'}]}
        self.assertFalse(verify_research_citations(lesson, RESEARCH))
        lesson['sections'][0]['explanation'] += ' [R999]'
        self.assertFalse(verify_research_citations(lesson, RESEARCH))
        self.assertFalse(substantively_uses_research(lesson, RESEARCH, SOURCE))

    def _generate(self, public):
        request = app.create_learning_request(['gardening'], SOURCE, 'Explain soil pH', 'general learning context')
        cultural = app.LocalDemoCulturalIntelligenceProvider().analyze(request.learner)
        calls = []
        class Research:
            def research(self, *args):
                return RESEARCH
        output = lesson_writer.build_offline_lesson(SOURCE, 'Explain soil pH', ['gardening'])
        # Valid structured source-grounded response, but no research citation.
        def transport(url, key, method, payload, timeout):
            calls.append(method)
            if method == 'GET':
                return {'id':'gpt-5.6-luna'}
            return {'status':'completed','model':'gpt-5.6-luna','id':'resp-offline-test',
                    'usage':{'input_tokens':300,'output_tokens':150,'total_tokens':450},
                    'output':[{'content':[{'type':'output_text','text':json.dumps(output)}]}]}
        env = {'HOSTED_PUBLIC_DEMO': '1' if public else '0',
               'IAL_TAVILY_ENRICHMENT':'0','IAL_AUDITED_BUDGET':'1',
               'IAL_WRITER_MAX_OUTPUT_TOKENS':'16000'}
        with patch.dict(os.environ,env,clear=False):
            provider = app.OpenAIResponsesLessonGenerationProvider('test-key','gpt-5.6-luna', transport=transport)
            provider.tavily_client = Research()
            try:
                response = provider.generate(request,cultural)
            except app.OpenAIProviderError as exc:
                response = exc
        return response, calls

    def test_public_mode_fails_over_once_without_web_claims_or_second_openai(self):
        response,calls = self._generate(True)
        self.assertIsInstance(response, app.LearningResponse)
        self.assertEqual(response.research_sources, ())
        self.assertNotIn('[R1]', response.generated_learning_response)
        self.assertEqual(response.provider_usage['research']['status'],'validation_fallback')
        self.assertIn('Source-only fallback', response.demo_label)
        self.assertEqual(calls.count('POST'), 1)

    def test_protected_mode_preserves_original_strict_failure(self):
        response,calls = self._generate(False)
        self.assertIsInstance(response, app.OpenAIProviderError)
        self.assertEqual(response.code,'research_grounding')
        self.assertEqual(calls.count('POST'), 1)

if __name__=='__main__':
    unittest.main()
