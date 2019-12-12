@load base/frameworks/cluster
@if (Version::number >= 20600)  # Config framework requires >= 2.6
@load base/frameworks/config
@endif

module Exporter;

export {
       ## The name of the function that we will collect arguments for.
       ## Stored as a record in case someone wants to use the input framework.
       type FunctionName: record {
       	    ## The name of the event, hook, or function for which we want arguments
	    name: string;
       };

       ## For this function name, we'll grab an arg and/or addl field, and add them as labels
       type AddlArgs: record {
	    ## The 0-indexed position of the argument to put in the 'arg' label
	    arg: int &default=-1;
	    ## The 0-indexed position of the argument to put in the 'addl' label
	    addl: int &default=-1;
       };

       ## This is the list of our functions for which we'll grab the additional arguments and store them as labels.
@if (Version::number >= 20600)  # Option keyword requires >= 2.6
       option arg_functions: table[string] of AddlArgs = { };
@else
       global arg_functions: table[string] of AddlArgs = { };
@endif

       ## The path to an Input framework file that will be used to set arg_functions.
       const conf_dat_path = cat(@DIR, "/conf.dat") &redef;

}

@if ( Cluster::is_enabled() && Cluster::node in Cluster::nodes && "control" in Cluster::nodes )
redef bind_port = count_to_port(port_to_count(Cluster::nodes[Cluster::node]$p) - port_to_count(Cluster::nodes["control"]$p) + port_to_count(base_port), tcp);
@endif

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
      {
      Reporter::info(fmt("Zeek Prometheus Exporter running on %s:%s", cat(bind_address), cat(base_port)));

      # Example of using the input framework to update this:
      Input::add_table([$source=conf_dat_path, $name="arg_func_input",
                        $idx=FunctionName, $val=AddlArgs, $destination=arg_functions]);
      }

event Input::end_of_data(name: string, source: string) {
     if ( name == "arg_func_input" )
     	for ( name in arg_functions )
	        Exporter::update_arg_functions(name, arg_functions[name]$arg, arg_functions[name]$addl);
}
