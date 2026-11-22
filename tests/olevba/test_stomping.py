import os
import unittest

from oletools.olevba import TYPE_OLE, VBA_Parser
from tests.test_utils import DATA_BASE_DIR


class TestVBAStompingDetails(unittest.TestCase):

    def make_parser(self, pcode, source):
        parser = VBA_Parser.__new__(VBA_Parser)
        parser.vba_stomping_detected = None
        parser.vba_stomping_items = []
        parser.type = TYPE_OLE
        parser.file_on_disk = True
        parser.pcodedmp_output = pcode
        parser.extract_pcode = lambda: pcode
        parser.get_vba_code_all_modules = lambda **kwargs: source
        return parser

    def test_reports_missing_identifiers_and_string_literals(self):
        parser = self.make_parser(
            '\tArgsLd HiddenFunction 0x0001\n\tLitStr 0x0005 "hidden"\n',
            'Sub VisibleFunction()\nEnd Sub\n',
        )

        self.assertTrue(parser.detect_vba_stomping())
        self.assertEqual(parser.vba_stomping_items, [
            {'kind': 'identifier', 'value': 'HiddenFunction'},
            {'kind': 'string literal', 'value': '"hidden"'},
        ])

    def test_has_no_items_when_pcode_tokens_exist_in_source(self):
        parser = self.make_parser(
            '\tArgsLd Mid$ 0x0002\n',
            'Debug.Print Mid$("abc", 1)\n',
        )

        self.assertFalse(parser.detect_vba_stomping())
        self.assertEqual(parser.vba_stomping_items, [])

    def test_detects_stomping_in_document_fixture_in_app_order(self):
        filename = os.path.join(DATA_BASE_DIR, 'olevba', 'macrofile_stomp.doc')
        parser = VBA_Parser(filename)
        try:
            self.assertTrue(parser.detect_vba_macros())
            self.assertTrue(parser.detect_vba_stomping())
            self.assertIn(
                {'kind': 'identifier', 'value': 'MsgBox'},
                parser.vba_stomping_items,
            )
            source = parser.get_vba_code_all_modules(include_pcode=False)
            analyzed_code = parser.get_vba_code_all_modules()
            self.assertNotIn('Document_Open', source)
            self.assertIn('Document_Open', analyzed_code)
            self.assertIn(('Suspicious', 'Shell', 'May run an executable file or a system command'), parser.analyze_macros())
            grouped_findings = parser.analyze_macros_by_source()
            self.assertIn(
                ('Suspicious', 'Shell', 'May run an executable file or a system command'),
                grouped_findings['pcode'],
            )
            self.assertNotIn(
                ('Suspicious', 'Shell', 'May run an executable file or a system command'),
                grouped_findings['vba_source'],
            )
            self.assertTrue(any(
                module[2] == 'VBA_P-code.txt'
                for module in parser.extract_all_macros()
            ))
        finally:
            parser.close()

    def test_ignores_suspicious_keywords_in_pcode_comments(self):
        filename = os.path.join(DATA_BASE_DIR, 'oleform', 'oleform-PR314.docm')
        parser = VBA_Parser(filename)
        try:
            self.assertTrue(parser.detect_vba_macros())
            pcode = parser.extract_pcode()
            self.assertIn('QuoteRem', pcode)
            parser.extract_pcode = lambda: pcode + '\n    QuoteRem 0x0000 0x0005 "Shell"\n'

            pcode_findings = parser.analyze_macros_by_source()['pcode']

            self.assertNotIn(
                ('Suspicious', 'Shell', 'May run an executable file or a system command'),
                pcode_findings,
            )
        finally:
            parser.close()


if __name__ == '__main__':
    unittest.main()