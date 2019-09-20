# ESnet_Zeek_Exporter/scripts/__load__.zeek


#### Exporter()

* **Namespace**

    Exporter



* **Imports**

    base/frameworks/cluster, base/frameworks/config


## Summary

### Runtime Options

| `Exporter::arg_functions`: `table` `&redef`

 | This is a table, indexed by the function name, of functions that we’ll grab additional arguments for, and store them as labels.

 |
### Redefinable Options

| `Exporter::base_port`: `port` `&redef`

      | For a cluster, we’ll dynamically assign port numbers,
beginning with the next one above this.

                                   |
| `Exporter::bind_address`: `addr` `&redef`

   | The address that the exporter will bind to.

                                                                                     |
| `Exporter::bind_port`: `port` `&redef`

      | The port that the exporter will bind to

                                                                                         |
### Types

| `Exporter::AddlArgs`: `record`

            | For this function name, we’ll grab an arg and/or addl field, and add them as labels

                                             |
| `Exporter::FunctionName`: `record`

        | The name of the function that we will collect arguments for.

                                                                    |
### Redefinitions

| `Exporter::arg_functions`: `table` `&redef`

 |                                                                                                                                 |
## Detailed Interface

### Runtime Options


#### Exporter::arg_functions()

* **Type**

    `table` [`string`] of `Exporter::AddlArgs`



* **Attributes**

    `&redef`



* **Default**

    `{}`



* **Redefinition**

    from /scripts/ESnet_Zeek_Exporter/scripts/__load__.zeek

    `+=`:

    ```
    net_weird = (coerce [$arg=0, $addl=1] to record { arg:int; addl:int; }), conn_weird = (coerce [$arg=0, $addl=2] to record { arg:int; addl:int; }), flow_weird = (coerce [$arg=0, $addl=3] to record { arg:int; addl:int; }), SumStats::cluster_get_result = (coerce [$arg=1] to record { arg:int; addl:int; }), SumStats::cluster_send_result = (coerce [$arg=1] to record { arg:int; addl:int; })
    ```


This is a table, indexed by the function name, of functions that we’ll grab additional arguments for, and store them as labels.

### Redefinable Options


#### Exporter::base_port()

* **Type**

    `port`



* **Attributes**

    `&redef`



* **Default**

    `9100/tcp`


For a cluster, we’ll dynamically assign port numbers,
beginning with the next one above this.


#### Exporter::bind_address()

* **Type**

    `addr`



* **Attributes**

    `&redef`



* **Default**

    `127.0.0.1`


The address that the exporter will bind to.


#### Exporter::bind_port()

* **Type**

    `port`



* **Attributes**

    `&redef`



* **Default**

    `9101/tcp`


The port that the exporter will bind to

### Types


#### Exporter::AddlArgs()

* **Type**

    `record`

    arg: `int` `&default` = `-1` `&optional`

        The 0-indexed position of the argument to put in the ‘arg’ label

    addl: `int` `&default` = `-1` `&optional`

        The 0-indexed position of the argument to put in the ‘addl’ label


For this function name, we’ll grab an arg and/or addl field, and add them as labels


#### Exporter::FunctionName()

* **Type**

    `record`

    name: `string`

        The name of the event, hook, or function for which we want arguments


The name of the function that we will collect arguments for.
Stored as a record in case someone wants to use the input framework.
