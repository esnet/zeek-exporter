# @TEST-EXEC: if command -v zeek; then zeek -NN ESnet::Zeek_Exporter > output; else bro -NN ESnet::Zeek_Exporter > output; done
# @TEST-EXEC: btest-diff output
