"""
Test basic functionality of olevba[3]
"""

import unittest
import os
from os.path import join, splitext
import re
import json

from oletools.olevba import (
    VBA_Parser, VBA_Scanner, _filter_xlm_only_findings,
    detect_autoexec, detect_base64_strings, detect_hex_strings,
    detect_hex_strings_with_locations, detect_suspicious,
)

# Directory with test data, independent of current working directory
from tests.test_utils import DATA_BASE_DIR, call_and_capture


class TestOlevbaBasic(unittest.TestCase):
    """Tests olevba basic functionality"""

    def test_scanner_ignores_vba_comments_without_losing_later_code(self):
        source = (
            "' Auto_Open\n"
            "Sub SafeRoutine()\n"
            "    Call Shell(\"safe\") ' Auto_Close\n"
            "    Rem Workbook_Open\n"
            "    Debug.Print \"O'Brien\"\n"
            "End Sub"
        )
        scanner = VBA_Scanner(source)
        findings = scanner.scan()
        keywords = [keyword for _, keyword, _ in findings]

        self.assertIn('Shell', keywords)
        self.assertNotIn('Auto_Open', keywords)
        self.assertNotIn('Auto_Close', keywords)
        self.assertNotIn('Workbook_Open', keywords)
        self.assertIn('O\'Brien', scanner.code)

    def test_open_indicator_requires_statement_position(self):
        def has_open_indicator(source):
            return any(
                description == 'May open a file'
                for _, description in detect_suspicious(source)
            )

        self.assertTrue(has_open_indicator('  Open filePath For Input As #1'))
        self.assertTrue(has_open_indicator('If ready Then: Open filePath For Input As #1'))
        self.assertTrue(has_open_indicator('If ready Then:Open filePath For Input As #1'))
        self.assertTrue(has_open_indicator('If ready Then Open filePath For Input As #1'))
        self.assertTrue(has_open_indicator('If ready Then Debug.Print "safe" Else Open filePath'))
        self.assertFalse(has_open_indicator('Private Sub Workbook_Open()\nEnd Sub'))
        self.assertFalse(has_open_indicator('Set workbook = Workbooks.Open(filePath)'))
        self.assertFalse(has_open_indicator('openFile = "safe"'))

    def test_run_indicator_requires_application_or_statement_position(self):
        def has_run_indicator(source):
            return any(
                description == 'May run an executable file or a system command'
                for _, description in detect_suspicious(source)
            )

        self.assertTrue(has_run_indicator('Application.Run "MacroName"'))
        self.assertTrue(has_run_indicator('result = Application.Run("MacroName")'))
        self.assertTrue(has_run_indicator('Dim AnyValue As Application\nAnyValue.Run "MacroName"'))
        self.assertTrue(has_run_indicator('DVZ.Run "MacroName"'))
        self.assertTrue(has_run_indicator('Run "MacroName"'))
        self.assertTrue(has_run_indicator('Call Run("MacroName")'))
        self.assertTrue(has_run_indicator('If ready Then: Run "MacroName"'))
        self.assertTrue(has_run_indicator('If ready Then Debug.Print "safe" Else Run "MacroName"'))
        self.assertFalse(has_run_indicator('Private Sub Run()\nEnd Sub'))
        self.assertFalse(has_run_indicator('RunMode = "safe"'))
        self.assertFalse(has_run_indicator(
            'Call PrintString("crotch: z    run: +shift", 5, 29, RED, SHADOW, FATSHADOW_BOTTOM)'
        ))

    def test_suspicious_detector_can_include_source_line(self):
        source = 'Private Sub Workbook_Open()\nEnd Sub\nOpen filePath For Input'

        self.assertEqual(
            detect_suspicious(source, include_locations=True),
            [('Open', 'May open a file', 3)],
        )
        self.assertEqual(
            detect_suspicious('Open filePath'),
            [('Open', 'May open a file')],
        )
        self.assertEqual(
            detect_suspicious('Open filePath For Input As #1'),
            [('Open', 'May open a file')],
        )
        self.assertEqual(detect_suspicious('Binary'), [])

    def test_xlm_dll_findings_require_xlm_macros(self):
        findings = [
            ('Suspicious', 'REGISTER', 'May call a DLL using Excel 4 Macros (XLM/XLF)'),
            ('Suspicious', 'REGISTER', 'May call a DLL using Excel 4 Macros (XLM/XLF) '
             '(obfuscation: Hex)'),
            ('Suspicious', 'REGISTER', 'Could contain a function that allows to call a DLL '
             'using Excel 4 Macros (XLM/XLF)'),
            ('Suspicious', 'Shell', 'May run an executable file or a system command'),
        ]

        self.assertEqual(
            _filter_xlm_only_findings(findings, contains_xlm_macros=False),
            [findings[-1]],
        )
        self.assertEqual(
            _filter_xlm_only_findings(findings, contains_xlm_macros=True),
            findings,
        )

    def test_pcode_dll_indicator_does_not_match_callback(self):
        source = (
            'FuncDefn (Declare PtrSafe Function mciSendString Lib "winmm.dll" '
            '(ByVal lpstrCommand As String, ByVal lpstrReturnString As String, '
            'ByVal uReturnLength As Long, ByVal hwndCallback As LongPtr) As Long)'
        )

        self.assertNotIn(
            'May call a DLL using Excel 4 Macros (XLM/XLF)',
            [description for _, description in detect_suspicious(source)],
        )

    def test_pcode_xlm_dll_indicator_requires_xlm_macros(self):
        filename = join(DATA_BASE_DIR, 'olevba', 'sample_with_vba.ppt')
        parser = VBA_Parser(filename)
        try:
            self.assertTrue(parser.detect_macros())
            self.assertFalse(parser.contains_xlm_macros)

            parser.extract_pcode = lambda: 'ArgsCall (Call) Example 0x0000'
            findings = parser.analyze_macros_by_source()
            self.assertNotIn(
                'May call a DLL using Excel 4 Macros (XLM/XLF)',
                [description for _, _, description in findings['pcode']],
            )
        finally:
            parser.close()

    def test_analysis_suppresses_xlm_dll_indicator_without_xlm_macros(self):
        filename = join(DATA_BASE_DIR, 'olevba', 'sample_with_vba.ppt')
        parser = VBA_Parser(filename)
        try:
            self.assertTrue(parser.detect_macros())
            self.assertFalse(parser.contains_xlm_macros)

            source = 'Sub Example()\nREGISTER "kernel32", "Foo"\nEnd Sub'
            parser.get_vba_code_all_modules = lambda **kwargs: source
            parser.extract_all_macros = lambda: [
                ('module', 'VBA/Module1', 'Module1', source)
            ]
            parser.extract_form_strings = lambda: []
            parser.detect_vba_stomping = lambda: False

            findings = parser.analyze_macros()
            self.assertNotIn(
                'May call a DLL using Excel 4 Macros (XLM/XLF)',
                [description for _, _, description in findings],
            )
        finally:
            parser.close()

    def test_autoexec_detector_can_include_source_line(self):
        source = 'Private Sub Workbook_Open()\nEnd Sub'

        self.assertEqual(
            detect_autoexec(source, include_locations=True),
            [('Workbook_Open', 'Runs when the Excel Workbook is opened', 1)],
        )
        self.assertEqual(
            detect_autoexec(source),
            [('Workbook_Open', 'Runs when the Excel Workbook is opened')],
        )

    def test_hex_strings_are_detected_only_inside_string_literals(self):
        source = 'If value > 2147483647 Then\nencoded = "41424344"'

        self.assertEqual(detect_hex_strings(source), [('41424344', 'ABCD')])
        self.assertEqual(
            detect_hex_strings_with_locations(source),
            [('41424344', 'ABCD', 2)],
        )

    def test_hex_strings_support_doubled_quotes_inside_literals(self):
        source = 'payload = "prefix ""41424344"" suffix"'

        self.assertEqual(detect_hex_strings(source), [('41424344', 'ABCD')])
        self.assertEqual(
            detect_hex_strings_with_locations(source),
            [('41424344', 'ABCD', 1)],
        )

    def test_hex_strings_remain_separate_across_doubled_quotes(self):
        source = 'payload = "41424344""4a4b4c4d"'

        self.assertEqual(
            detect_hex_strings(source),
            [('41424344', 'ABCD'), ('4a4b4c4d', 'JKLM')],
        )

    def test_hex_strings_are_detected_in_adjacent_literals(self):
        source = 'payload = "41424344" & "4a4b4c4d"'

        self.assertEqual(
            detect_hex_strings(source),
            [('41424344', 'ABCD'), ('4a4b4c4d', 'JKLM')],
        )

    def test_hex_strings_ignore_empty_and_unterminated_literals(self):
        source = 'empty = """"\nunclosed = "not closed\npayload = "41424344"'

        self.assertEqual(detect_hex_strings(source), [('41424344', 'ABCD')])
        self.assertEqual(
            detect_hex_strings_with_locations(source),
            [('41424344', 'ABCD', 3)],
        )

    def test_base64_detector_ignores_misc_label(self):
        for value in ('MISC', 'misc', 'vKey', 'hwndCallback', 'Gold'):
            with self.subTest(value=value):
                self.assertEqual(detect_base64_strings(f'value = "{value}"'), [])
        self.assertEqual(detect_base64_strings('payload = "TWFu"'), [('TWFu', 'Man')])

    def test_hex_strings_ignore_vba_attribute_metadata(self):
        source = (
            'Attribute VB_Name = "ЭтаКнига"\n'
            'Attribute VB_Base = "0{00020819-0000-0000-C000-000000000046}"\n'
            'Attribute VB_GlobalNameSpace = False\n'
            'Attribute VB_Creatable = False\n'
            'payload = "00020819"'
        )

        self.assertEqual(detect_hex_strings(source), [('00020819', '\x00\x02\x08\x19')])
        self.assertEqual(
            detect_hex_strings_with_locations(source),
            [('00020819', '\x00\x02\x08\x19', 5)],
        )

    def test_hex_string_finding_includes_vba_source_location(self):
        filename = join(DATA_BASE_DIR, 'olevba', 'sample_with_vba.ppt')
        parser = VBA_Parser(filename)
        source = (
            'Sub Example()\nvalue = 2147483647\n'
            'encoded = "41424344"\nmetadata = "00020819"\nEnd Sub'
        )
        try:
            parser.get_vba_code_all_modules = lambda **kwargs: source
            parser.extract_macros = lambda: [
                ('module', 'VBA/Module1', 'Module1', source)
            ]
            parser.extract_form_strings = lambda: []
            parser.extract_pcode = lambda: ''

            findings = parser.analyze_macros_by_source()

            self.assertIn(('Hex String', 'ABCD', '41424344'), findings['vba_source'])
            self.assertIn({
                'type': 'Hex String',
                'keyword': 'ABCD',
                'description': '41424344',
                'module_index': 0,
                'module_name': 'Module1',
                'line_number': 3,
            }, findings['vba_source_locations'])
            self.assertIn(('Hex String', '\x00\x02\x08\x19', '00020819'), findings['vba_source'])
            self.assertIn({
                'type': 'Hex String',
                'keyword': '\x00\x02\x08\x19',
                'description': '00020819',
                'module_index': 0,
                'module_name': 'Module1',
                'line_number': 4,
            }, findings['vba_source_locations'])
        finally:
            parser.close()

    def test_text_behaviour(self):
        """Test behaviour of olevba when presented with pure text file."""
        self.do_test_behaviour('text')

    def test_empty_behaviour(self):
        """Test behaviour of olevba when presented with pure text file."""
        self.do_test_behaviour('empty')

    def do_test_behaviour(self, filename):
        """Helper for test_{text,empty}_behaviour."""
        input_file = join(DATA_BASE_DIR, 'basic', filename)
        output, _ = call_and_capture('olevba', args=(input_file, ))

        # check output
        self.assertTrue(re.search(r'^Type:\s+Text\s*$', output, re.MULTILINE),
                        msg='"Type: Text" not found in output:\n' + output)
        self.assertTrue(re.search(r'^No suspicious .+ found.$', output,
                                  re.MULTILINE),
                        msg='"No suspicous...found" not found in output:\n' + \
                            output)
        self.assertNotIn('error', output.lower())

        # check warnings
        for line in output.splitlines():
            if line.startswith('WARNING ') and 'encrypted' in line:
                continue   # encryption warnings are ok
            elif line.startswith('WARNING '):
                self.fail('Found warning in output line: "{}"'
                          .format(line.rstrip()))
        # TODO: I disabled this test because we do not log "not encrypted" as warning anymore
        # to avoid other issues.
        # If we really want to test this, then the test should be run with log level INFO:
        # self.assertIn('not encrypted', output)

    def test_rtf_behaviour(self):
        """Test behaviour of olevba when presented with an rtf file."""
        input_file = join(DATA_BASE_DIR, 'msodde', 'RTF-Spec-1.7.rtf')
        output, ret_code = call_and_capture('olevba', args=(input_file, ),
                                            accept_nonzero_exit=True)

        # check that return code is olevba.RETURN_OPEN_ERROR
        self.assertEqual(ret_code, 5)

        # check output:
        self.assertIn('FileOpenError', output)
        self.assertIn('is RTF', output)
        self.assertIn('rtfobj', output)
        # TODO: I disabled this test because we do not log "not encrypted" as warning anymore
        # to avoid other issues.
        # If we really want to test this, then the test should be run with log level INFO:
        # self.assertIn('not encrypted', output)

        # check warnings
        for line in output.splitlines():
            if line.startswith('WARNING ') and 'encrypted' in line:
                continue   # encryption warnings are ok
            elif line.startswith('WARNING '):
                self.fail('Found warning in output line: "{}"'
                          .format(line.rstrip()))

    def test_crypt_return(self):
        """
        Test that encrypted files give a certain return code.

        Currently, only the encryption applied by Office 2010 (CryptoApi RC4
        Encryption) is tested.
        """
        CRYPT_DIR = join(DATA_BASE_DIR, 'encrypted')
        CRYPT_RETURN_CODE = 9
        ADD_ARGS = [], ['-d', ], ['-a', ], ['-j', ], ['-t', ]   # only 1st file
        EXCEPTIONS = ['autostart-encrypt-standardpassword.xls',   # These ...
                      'autostart-encrypt-standardpassword.xlsm',  # files ...
                      'autostart-encrypt-standardpassword.xlsb',  # are ...
                      'dde-test-encrypt-standardpassword.xls',    # automati...
                      'dde-test-encrypt-standardpassword.xlsx',   # ...cally...
                      'dde-test-encrypt-standardpassword.xlsm',   # decrypted.
                      'dde-test-encrypt-standardpassword.xlsb']
        for filename in os.listdir(CRYPT_DIR):
            if filename in EXCEPTIONS:
                continue
            full_name = join(CRYPT_DIR, filename)
            for args in ADD_ARGS:
                _, ret_code = call_and_capture('olevba',
                                               args=[full_name, ] + args,
                                               accept_nonzero_exit=True)
                self.assertEqual(ret_code, CRYPT_RETURN_CODE,
                                 msg='Wrong return code {} for args {}'\
                                     .format(ret_code, args + [filename, ]))

                # test only first file with all arg combinations, others just
                # without arg (test takes too long otherwise
                ADD_ARGS = ([], )

    def test_xlm(self):
        """Test that xlm macros are found."""
        XLM_DIR = join(DATA_BASE_DIR, 'excel4-macros')
        ADD_ARGS = ['-j']

        for filename in os.listdir(XLM_DIR):
            full_name = join(XLM_DIR, filename)
            suffix = splitext(filename)[1]
            out_str, ret_code = call_and_capture('olevba',
                                                 args=[full_name, ] + ADD_ARGS,
                                                 accept_nonzero_exit=True,
                                                 exclude_stderr=True)
            output = json.loads(out_str)
            self.assertGreaterEqual(len(output), 2)
            self.assertEqual(output[0]['type'], 'MetaInformation')
            self.assertEqual(output[0]['script_name'], 'olevba')
            for entry in output[1:]:
                if entry['type'] in ('msg', 'warning'):
                    continue    # ignore messages
                result = entry
                break
            self.assertTrue(result['json_conversion_successful'])
            if suffix == '.xlsb':
                # TODO: cannot extract xlm macros from XLSB files yet
                self.assertEqual(result['macros'], [])
            elif suffix in ('.xltm', '.xlsm'):
                self.assertTrue(result['macros'])
                types = [entry['type'] for entry in result['analysis']]
                keywords = [entry['keyword'] for entry in result['analysis']]
                self.assertIn('XLM macro', keywords)
                self.assertIn('Suspicious', types)
            else:
                code = result['macros'][0]['code']
                if suffix == '.slk':
                    self.assertIn('Excel 4 macros extracted', code)
                else:
                    self.assertIn('Excel 4.0 macro sheet', code)
                self.assertIn('Auto_Open', code)
                if 'excel5' not in filename:    # TODO: is not found in excel5
                    self.assertIn('ALERT(', code)
                self.assertIn('HALT()', code)

                self.assertIn(len(result['analysis']), (2, 3))
                types = [entry['type'] for entry in result['analysis']]
                keywords = [entry['keyword'] for entry in result['analysis']]
                self.assertIn('Auto_Open', keywords)
                self.assertIn('XLM macro', keywords)
                self.assertIn('AutoExec', types)
                self.assertIn('Suspicious', types)

    def test_xlm_openxml_analysis_is_separate_from_vba_source(self):
        filename = join(DATA_BASE_DIR, 'excel4-macros', 'excel4_sample_macro.xlsm')
        parser = VBA_Parser(filename)
        try:
            self.assertTrue(parser.detect_xlm_macros())
            xlm_sources = parser.extract_xlm_macros()
            self.assertEqual(len(xlm_sources), 1)
            self.assertEqual(xlm_sources[0][0], 'Sheet Macro1 (xl/macrosheets/sheet1.xml)')
            self.assertIn('ALERT(', xlm_sources[0][1])
            self.assertIn('HALT()', xlm_sources[0][1])

            vba_source = parser.get_vba_code_all_modules(include_pcode=False, include_xlm=False)
            self.assertNotIn('ALERT(', vba_source)
            self.assertNotIn('Excel 4.0 macro sheet found', vba_source)

            source_findings = parser.analyze_macros_by_source()['vba_source']
            xlm_findings = parser.analyze_xlm_macros()
            self.assertNotIn('XLM macro', [finding[1] for finding in source_findings])
            self.assertIn('XLM macro', [finding[1] for finding in xlm_findings])
        finally:
            parser.close()

    def test_xlm_legacy_analysis_is_separate_from_vba_source(self):
        filename = join(DATA_BASE_DIR, 'excel4-macros', 'excel4_sample_macro.xls')
        parser = VBA_Parser(filename)
        try:
            self.assertTrue(parser.detect_xlm_macros())
            xlm_sources = parser.extract_xlm_macros()
            self.assertEqual(len(xlm_sources), 1)
            self.assertIn('Excel 4.0 macro sheet: Macro', xlm_sources[0][0])
            self.assertIn('A1: =ALERT(', xlm_sources[0][1])
            self.assertIn('A2: =HALT()', xlm_sources[0][1])

            source_findings = parser.analyze_macros_by_source()['vba_source']
            xlm_findings = parser.analyze_xlm_macros()
            self.assertNotIn('XLM macro', [finding[1] for finding in source_findings])
            self.assertIn('XLM macro', [finding[1] for finding in xlm_findings])
        finally:
            parser.close()

    def test_dir_stream_record_project_compat_version(self):
        """Test PROJECTCOMPATVERSION record on dir stream with a ppt file."""
        input_file = join(DATA_BASE_DIR, 'olevba', 'sample_with_vba.ppt')
        output, ret_code = call_and_capture('olevba', args=(input_file, "--loglevel", "debug"))

        # check return code
        self.assertEqual(ret_code, 0)

        # not expected string:
        self.assertNotIn('invalid value for PROJECTLCID_Id expected 0002 got', output)
        self.assertNotIn('Error in _extract_vba', output)

        # compat version in debug mode:
        self.assertIn('compat version: 2', output)

        # vba contents:
        self.assertIn('Sub Action_Click()\n  MsgBox "The action button clicked!"\nEnd Sub', output)


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
