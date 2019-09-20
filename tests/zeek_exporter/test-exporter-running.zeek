# @TEST-EXEC: command -v zeek && btest-bg-run zeek zeek -b %INPUT || true
# @TEST-EXEC: command -v zeek || btest-bg-run zeek bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: curl localhost:9101/metrics | cut -f 1 -d '{' | sort | uniq | grep -v '#' | grep zeek_ > metrics
# @TEST-EXEC: btest-diff metrics
