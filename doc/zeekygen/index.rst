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
========================================================================== =========================================================================================================
:zeek:id:`Exporter::arg_functions`: :zeek:type:`table` :zeek:attr:`&redef` This is the list of our functions for which we'll grab the additional arguments and store them as labels.
========================================================================== =========================================================================================================

Redefinable Options
###################
=========================================================================== ===========================================================================
:zeek:id:`Exporter::base_port`: :zeek:type:`port` :zeek:attr:`&redef`       For a cluster, we'll dynamically assign port numbers,
                                                                            beginning with the next one above this.
:zeek:id:`Exporter::bind_address`: :zeek:type:`addr` :zeek:attr:`&redef`    The address that the exporter will bind to.
:zeek:id:`Exporter::bind_port`: :zeek:type:`port` :zeek:attr:`&redef`       The port that the exporter will bind to
:zeek:id:`Exporter::conf_dat_path`: :zeek:type:`string` :zeek:attr:`&redef` The path to an Input framework file that will be used to set arg_functions.
=========================================================================== ===========================================================================

Types
#####
======================================================== ===================================================================================
:zeek:type:`Exporter::AddlArgs`: :zeek:type:`record`     For this function name, we'll grab an arg and/or addl field, and add them as labels
:zeek:type:`Exporter::FunctionName`: :zeek:type:`record` The name of the function that we will collect arguments for.
======================================================== ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Exporter::arg_functions

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Exporter::AddlArgs`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   This is the list of our functions for which we'll grab the additional arguments and store them as labels.

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

.. zeek:id:: Exporter::conf_dat_path

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"$(zeek-config --plugin_dir)/ESnet_Zeek_Exporter/scripts/conf.dat"``

   The path to an Input framework file that will be used to set arg_functions.

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


