@load base/frameworks/cluster
@load base/frameworks/config

module Exporter;

export {
       ## The address that the exporter will bind to.
       const bind_address = 127.0.0.1 &redef;

       ## For a cluster, we'll dynamically assign port numbers,
       ## beginning with the next one above this.
       const base_port = 9100/tcp &redef;

       ## The port that the exporter will bind to
       const bind_port = count_to_port(port_to_count(base_port) + 1, tcp) &redef;

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
       option arg_functions: table[string] of AddlArgs = { };

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
      # Example of using the input framework to update this:
      Input::add_table([$source=conf_dat_path, $name="arg_func_input",
                        $idx=FunctionName, $val=AddlArgs, $destination=arg_functions]);
      }

event Input::end_of_data(name: string, source: string) {
     if ( name == "arg_func_input" )
     	for ( name in arg_functions )
	        Exporter::update_arg_functions(name, arg_functions[name]$arg, arg_functions[name]$addl);
}
