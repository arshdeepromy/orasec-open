import json

from orasec.survey.ui.forms import MultiExampleField, MultiWidgetBasic
from unittests.orasec_test_case import OraSecTestCase


class TestSurveyChoiceWidget(OraSecTestCase):
    def test_compress_returns_json_string(self):
        field = MultiExampleField(required=False)
        values = ["a", "b", "c", None, None, None]
        compressed = field.compress(values)

        self.assertIsInstance(compressed, str)
        self.assertEqual(json.loads(compressed), values)

    def test_decompress_round_trips(self):
        widget = MultiWidgetBasic()
        values = ["red", "green", "blue", "yellow", None, None]
        compressed = json.dumps(values)

        self.assertEqual(widget.decompress(compressed), values)

    def test_decompress_empty_returns_blank_list(self):
        widget = MultiWidgetBasic()
        self.assertEqual(widget.decompress(None), [None, None, None, None, None, None])
        self.assertEqual(widget.decompress(""), [None, None, None, None, None, None])
