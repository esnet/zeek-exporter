# @TEST-EXEC: zeek -NN ESnet::Zeek_Exporter |grep listening_ports | cut -f 3- -d: > output
# @TEST-EXEC: btest-diff output
