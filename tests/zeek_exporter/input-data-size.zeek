# @TEST-EXEC: if ! command -v zeek; then alias zeek bro; fi
# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "arg_func_input" )
		{
		print "net_weird";
		print "net_weird" in Exporter::arg_functions;
		}
	}
