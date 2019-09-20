# @TEST-EXEC: command -v zeek && zeek -NN ESnet::Zeek_Exporter | grep listening_ports | cut -f 3- -d: > output || true
# @TEST-EXEC: command -v zeek || bro -NN ESnet::Zeek_Exporter | grep listening_ports | cut -f 3- -d: > output
# @TEST-EXEC: btest-diff output
