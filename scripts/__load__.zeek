module Exporter;

export {
       ## The address that the exporter will bind to.
       const bind_address = 127.0.0.1 &redef;

       ## For a cluster, we'll dynamically assign port numbers,
       ## beginning with the next one above this.
       const base_port = 9100/tcp &redef;

       ## The port that the exporter will bind to
       const bind_port = count_to_port(port_to_count(base_port) + 1, tcp) &redef;
}