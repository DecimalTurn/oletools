import unittest

from oletools.olevba import TYPE_OLE, VBA_Parser


class TestVBAStompingDetails(unittest.TestCase):

    def make_parser(self, pcode, source):
        parser = VBA_Parser.__new__(VBA_Parser)
        parser.vba_stomping_detected = None
        parser.vba_stomping_items = []
        parser.type = TYPE_OLE
        parser.file_on_disk = True
        parser.pcodedmp_output = pcode
        parser.extract_pcode = lambda: pcode
        parser.get_vba_code_all_modules = lambda: source
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


if __name__ == '__main__':
    unittest.main()