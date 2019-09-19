:tocdepth: 3

ESnet_Zeek_Exporter/scripts/__load__.zeek
=========================================
.. zeek:namespace:: Exporter


:Namespace: Exporter
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/config </scripts/base/frameworks/config/index>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================== ===============================================================================================================================
:zeek:id:`Exporter::arg_functions`: :zeek:type:`table` :zeek:attr:`&redef` This is a table, indexed by the function name, of functions that we'll grab additional arguments for, and store them as labels.
========================================================================== ===============================================================================================================================

Redefinable Options
###################
======================================================================== =====================================================
:zeek:id:`Exporter::base_port`: :zeek:type:`port` :zeek:attr:`&redef`    For a cluster, we'll dynamically assign port numbers,
                                                                         beginning with the next one above this.
:zeek:id:`Exporter::bind_address`: :zeek:type:`addr` :zeek:attr:`&redef` The address that the exporter will bind to.
:zeek:id:`Exporter::bind_port`: :zeek:type:`port` :zeek:attr:`&redef`    The port that the exporter will bind to
======================================================================== =====================================================

Types
#####
======================================================== ===================================================================================
:zeek:type:`Exporter::AddlArgs`: :zeek:type:`record`     For this function name, we'll grab an arg and/or addl field, and add them as labels
:zeek:type:`Exporter::FunctionName`: :zeek:type:`record` The name of the function that we will collect arguments for.
======================================================== ===================================================================================

Redefinitions
#############
========================================================================== =
:zeek:id:`Exporter::arg_functions`: :zeek:type:`table` :zeek:attr:`&redef` 
========================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Exporter::arg_functions

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Exporter::AddlArgs`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/ESnet_Zeek_Exporter/scripts/__load__.zeek`

      ``+=``::

         net_weird = (coerce [$arg=0, $addl=1] to record { arg:int; addl:int; }), conn_weird = (coerce [$arg=0, $addl=2] to record { arg:int; addl:int; }), flow_weird = (coerce [$arg=0, $addl=3] to record { arg:int; addl:int; }), SumStats::cluster_get_result = (coerce [$arg=1] to record { arg:int; addl:int; }), SumStats::cluster_send_result = (coerce [$arg=1] to record { arg:int; addl:int; })


   This is a table, indexed by the function name, of functions that we'll grab additional arguments for, and store them as labels.

Redefinable Options
###################
.. zeek:id:: Exporter::base_port

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9100/tcp``

   For a cluster, we'll dynamically assign port numbers,
   beginning with the next one above this.

.. zeek:id:: Exporter::bind_address

   :Type: :zeek:type:`addr`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``127.0.0.1``

   The address that the exporter will bind to.

.. zeek:id:: Exporter::bind_port

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9101/tcp``

   The port that the exporter will bind to

Types
#####
.. zeek:type:: Exporter::AddlArgs

   :Type: :zeek:type:`record`

      arg: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`
         The 0-indexed position of the argument to put in the 'arg' label

      addl: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`
         The 0-indexed position of the argument to put in the 'addl' label

   For this function name, we'll grab an arg and/or addl field, and add them as labels

.. zeek:type:: Exporter::FunctionName

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         The name of the event, hook, or function for which we want arguments

   The name of the function that we will collect arguments for.
   Stored as a record in case someone wants to use the input framework.


