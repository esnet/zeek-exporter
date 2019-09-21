# @TEST-EXEC: if command -v zeek; then btest-bg-run zeek zeek %INPUT; else btest-bg-run zeek bro %INPUT; fi
# @TEST-EXEC: sleep 3; curl localhost:45713/metrics | cut -f 1 -d '{' | sort | uniq | grep -v '#' | grep zeek_ > metrics
# @TEST-EXEC: btest-bg-wait -k 2
# @TEST-EXEC: btest-diff metrics

redef exit_only_after_terminate=T;
redef Exporter::bind_port=45713/tcp;

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
      {
      Reporter::info("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
      }
