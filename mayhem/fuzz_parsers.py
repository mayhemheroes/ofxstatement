#!/usr/bin/env python3
import decimal
import random

import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports(include=['ofxstatement']):
    from ofxstatement.parser import CsvStatementParser
    from ofxstatement import ofx
    from ofxstatement.statement import Statement, StatementLine, BankAccount, Currency

from datetime import datetime
from decimal import  Decimal

# Exceptions
import csv

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        if fdp.ConsumeBool():
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as fin:
                parser = CsvStatementParser(fin).parse()
        else:
            # Create a random statement
            statement = Statement(fdp.ConsumeRandomString(), fdp.ConsumeRandomString(), fdp.ConsumeRandomString())
            for _ in range(fdp.ConsumeIntInRange(0, 100)):
                stmt_line = StatementLine(
                    str(fdp.ConsumeInt(1)),
                    datetime(fdp.ConsumeIntInRange(1, 9999), fdp.ConsumeIntInRange(1, 12), fdp.ConsumeIntInRange(1, 28)),
                    fdp.ConsumeRandomString(),
                    Decimal(fdp.ConsumeRandomString())
                )
                if fdp.ConsumeBool():
                    stmt_line.payee = fdp.ConsumeRandomString()
                if fdp.ConsumeBool():
                    stmt_line.bank_account_to = BankAccount(fdp.ConsumeRandomString(), fdp.ConsumeRandomString())
                    if fdp.ConsumeBool():
                        stmt_line.bank_account_to.branch_id = fdp.ConsumeRandomString()
                if fdp.ConsumeBool():
                    stmt_line.currency = Currency(fdp.ConsumeRandomString())
                if fdp.ConsumeBool():
                    stmt_line.orig_currency = Currency(fdp.ConsumeRandomString(), Decimal(fdp.ConsumeRandomString()))
                statement.lines.append(stmt_line)

            ofx.OfxWriter(statement).toxml()
    except (AssertionError, csv.Error, decimal.InvalidOperation):
        return -1
    except Exception as e:
        print(type(e))
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
