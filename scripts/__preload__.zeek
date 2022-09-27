@load base/frameworks/cluster

module Exporter;

export {
	## The address that the exporter will bind to.
	const bind_address = 0.0.0.0 &redef;

	## For a cluster, we'll dynamically assign port numbers,
	## beginning with the next one above this.
	const base_port = 9100/tcp &redef;

        ## Tell the exporter to track function lineage (resource intensive)
        const track_lineage = F &redef;

	## The port that the exporter will bind to
@if ( getenv("ZEEK_EXPORTER_PORT") != "" )
	const bind_port = count_to_port(to_count(split_string1(getenv("ZEEK_EXPORTER_PORT"), /\//)[0]), tcp) &redef; # Use the env var if we have it
@else
	@if ( ! reading_live_traffic() )
	const bind_port = count_to_port(1024 + rand(64500), tcp) &redef; # If we're not running on live traffic, use a random port
	@else
	const bind_port = count_to_port(port_to_count(base_port) + 1, tcp) &redef;
	@endif
@endif

	## Updates the internal list of functions that we grab some parameters for
	##
	## name: The name of the function
	##
	## arg: The 0-indexed field in the val_list that we'll put in the 'arg' label
	##
	## addl: The 0-indexed field in the val_list that we'll put in the 'addl' label
	global update_arg_functions: function(name: string, arg: int, addl: int);
}

function update_arg_functions(name: string, arg: int, addl: int)
	{
	# noop. This is handled in the plugin
	;
	}

# Incremement the port for each cluster member
@if ( Cluster::is_enabled() && Cluster::node in Cluster::nodes && "control" in Cluster::nodes && Cluster::node != "control" )
redef bind_port = count_to_port(port_to_count(Cluster::nodes[Cluster::node]$p) - port_to_count(Cluster::nodes["control"]$p) + port_to_count(base_port), tcp);
@endif

