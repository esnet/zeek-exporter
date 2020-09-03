# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: zeek -b -NN | grep Exporter
# @TEST-EXEC: zeek %INPUT
