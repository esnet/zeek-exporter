DIAG=diag.log
JUNIT=.btest_output.xml

all: cleanup btest-verbose

# Showing all tests.
btest-verbose:
	@btest -j -f $(DIAG) -x $(JUNIT) || { cat $(DIAG); exit 1 }

brief: cleanup btest-brief

# Brief output showing only failed tests.
btest-brief:
	@btest -j -b -f $(DIAG) -x $(JUNIT) || { cat $(DIAG); exit 1 }

coverage:
	@./Scripts/coverage

cleanup:
	@rm -f $(DIAG) $(JUNIT)
	@rm -f .tmp/script-coverage/*
	@find ../../ -name "*.gcov" -exec rm {} \;

distclean: cleanup
	@rm -rf .btest.failed.dat \
		.tmp/

.PHONY: all btest-verbose brief btest-brief cleanup
