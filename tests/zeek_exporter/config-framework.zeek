# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: sleep 3
# @TEST-EXEC: curl 127.0.0.1:45713/metrics | grep Sometimes
# @TEST-EXEC: btest-bg-wait -k 2

@load base/frameworks/notice/weird

redef exit_only_after_terminate=T;

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "arg_func_input" )
		for ( name in Exporter::arg_functions )
			Exporter::update_arg_functions(name, Exporter::arg_functions[name]$arg, Exporter::arg_functions[name]$addl);

	Reporter::net_weird("Sometimes we don't have any log writes, and thus nothing shows up for that metric.");
	Log::flush(Weird::LOG);
	}
