# @TEST-PORT: ZEEK_EXPORTER_PORT
# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: sleep 4
# @TEST-EXEC: bash -c 'curl 127.0.0.1:${ZEEK_EXPORTER_PORT/tcp/metrics} | grep Sometimes || ( curl 127.0.0.1:${ZEEK_EXPORTER_PORT/tcp/metrics} | grep net_weird 1>&2; exit 1 )'
# @TEST-EXEC: btest-bg-wait -k 2

@load base/frameworks/notice/weird

redef exit_only_after_terminate=T;

global gen_weird: event();

event gen_weird()
	{
	Reporter::net_weird("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
	Log::flush(Weird::LOG);
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "arg_func_input" )
		for ( name in Exporter::arg_functions )
			Exporter::update_arg_functions(name, Exporter::arg_functions[name]$arg, Exporter::arg_functions[name]$addl);

	schedule 2 sec { gen_weird() };
	}
