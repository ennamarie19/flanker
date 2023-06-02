#!/usr/bin/env python3
import atheris
import sys
import fuzz_helpers
import io
from contextlib import contextmanager


with atheris.instrument_imports(include=['flanker']):
    from flanker.addresslib import address

from idna import InvalidCodepoint, IDNAError

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.BytesIO()
    sys.stderr = io.BytesIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 3)
    try:
        with nostdout():
            if choice == 0:
                address.parse(fdp.ConsumeRemainingString())
            elif choice == 1:
                address.parse_list(fuzz_helpers.build_fuzz_list(fdp, [str]))
            elif choice == 2:
                address.validate_address(fdp.ConsumeRemainingString())
            elif choice == 3:
                address.validate_list(fuzz_helpers.build_fuzz_list(fdp, [str]))

    except (TypeError, InvalidCodepoint, ModuleNotFoundError, IDNAError):
        return -1
def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
