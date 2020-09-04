# @TEST-PORT: ZEEK_EXPORTER_PORT
# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
	{
	Reporter::net_weird("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
	Log::flush(Weird::LOG);
	}

