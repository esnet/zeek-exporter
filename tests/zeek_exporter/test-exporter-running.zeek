# @TEST-PORT: ZEEK_EXPORTER_PORT
# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: bash -c 'sleep 3; curl 127.0.0.1:${ZEEK_EXPORTER_PORT/tcp/metrics} | cut -f 1 -d "{" | sort | uniq | grep -v "#" | grep zeek_ > metrics'
# @TEST-EXEC: btest-bg-wait -k 2
# @TEST-EXEC: btest-diff metrics

@load base/frameworks/notice/weird

redef exit_only_after_terminate=T;

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
	{
	Reporter::net_weird("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
	Log::flush(Weird::LOG);
	}
