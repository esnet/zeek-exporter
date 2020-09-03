# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff reporter.log

redef Exporter::bind_port=45713/tcp;
redef Exporter::bind_address=0.0.0.0;

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
	{
	Reporter::info("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
	Log::flush(Reporter::LOG);
	}

