# @TEST-PORT: ZEEK_EXPORTER_PORT
# @TEST-EXEC: $ZEEK -b %INPUT > output
# @TEST-EXEC: btest-diff output

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "arg_func_input" )
		{
		print "net_weird";
		print "net_weird" in Exporter::arg_functions;
		}
	}
