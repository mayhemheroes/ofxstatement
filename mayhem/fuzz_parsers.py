#!/usr/bin/env python3
import random

import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports(include=['ofxstatement']):
    from ofxstatement.parser import CsvStatementParser
    from ofxstatement import ofx
    from ofxstatement.statement import Statement

# Exceptions
import csv

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as fin:
            statement = CsvStatementParser(fin).parse()
            ofx.OfxWriter(statement).toxml()
    except (AssertionError, csv.Error):
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
