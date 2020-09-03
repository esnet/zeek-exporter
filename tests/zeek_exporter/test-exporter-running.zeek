# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: btest-bg-run zeek zeek %INPUT
# @TEST-EXEC: sleep 3; curl 127.0.0.1:45713/metrics | cut -f 1 -d '{' | sort | uniq | grep -v '#' | grep zeek_ > metrics
# @TEST-EXEC: btest-bg-wait -k 2
# @TEST-EXEC: btest-diff metrics

redef exit_only_after_terminate=T;

redef Exporter::bind_port=45713/tcp;
redef Exporter::bind_address=0.0.0.0;

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
	{
	Reporter::net_weird("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
	Log::flush(Weird::LOG);
	}
