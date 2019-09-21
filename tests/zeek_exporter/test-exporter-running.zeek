# @TEST-EXEC: if command -v zeek; then btest-bg-run zeek zeek -b %INPUT; else btest-bg-run zeek bro -b %INPUT; fi
# @TEST-EXEC: sleep 3; curl localhost:9101/metrics | cut -f 1 -d '{' | sort | uniq | grep -v '#' | grep zeek_ > metrics
# @TEST-EXEC: btest-bg-wait -k 2
# @TEST-EXEC: btest-diff metrics

redef exit_only_after_terminate=T;
