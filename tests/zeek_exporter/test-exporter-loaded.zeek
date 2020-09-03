# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: zeek -NN | grep Exporter
# @TEST-EXEC: zeek %INPUT

redef Exporter::bind_port=45713/tcp;
redef Exporter::bind_address=0.0.0.0;
