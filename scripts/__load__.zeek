module Exporter;

export {
       ## The address that the exporter will bind to.
       const bind_address = 0.0.0.0 &redef;

       ## For a cluster, we'll dynamically assign port numbers,
       ## beginning with the next one above this.
       const base_port = 9100/tcp &redef;

       ## The port that the exporter will bind to
       const bind_port = count_to_port(port_to_count(base_port) + 1, tcp) &redef;

       ## Updates the internal list of functions that we grab some parameters for
       ##
       ## name: The name of the function
       ##
       ## arg: The 0-indexed field in the val_list that we'll put in the 'arg' label
       ##
       ## addl: The 0-indexed field in the val_list that we'll put in the 'addl' label
       global update_arg_functions: function(name: string, arg: int, addl: int);
}
