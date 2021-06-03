========
INT-SINK
========

The purpose of this software is to remove In-Band Network Telemetry(INT)
data from packets through the use of XDP and eBPF.

Compilation Dependencies
------------------------

In order to compile the INT-SINK project,
the following two tasks must be completed.

- Initialize git submodules
- Install bpftool v5.12.0

This project pulls the ``libbpf`` source through a git submodule.
``libbpf`` provides a library for attaching and manipulating BPF programs.
To initialize this module run the following commands from the project root directory:

.. code:: bash

    git submodule init
    git submodule update

This project uses ``bpftool`` to link BPF ELF files together.
Linking of ELF files using ``bpftool`` is only available in
v5.12.0 or greater. To get ``bpftool`` of v5.12.0 or greater,
we suggest building and installing it from the bpf-next_
branch of the linux kernel source. The ``bpftool``
can be installed from ``tools/bpf/bpftool/`` directory of the
kernel source by running the following command:

.. code:: bash

    make install

.. _bpf-next: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/


Compiling
---------

Before compilation can begin, all compilation dependencies
must be satisfied.
To compile this project, enter the ``src/`` directory
and run the following command:

.. code:: bash

    make all

This will produce the program ``./int_remover`` in the ``src/user/`` directory.
``./int_remover`` can function as a stand alone executable,
and can be moved from there.

Execution Dependencies
----------------------

In order to execute ``./int_remover`` and any other binaries produced by this project,
the following dependencies must be satisfied:

- Running Linux kernel v5.4 or greater
- BPF enabled on Linux Kernel

If you are unsure of which kernel version you are running,
you can check with the following command:

.. code:: bash

    uname -r

To check if bpf is enabled on your current system,
run the following command:

.. code:: bash

    cat /boot/config-$(uname -r) | grep CONFIG_BPF=y

Executing
---------

To execute ``./int_remover``, run the following command:

.. code:: bash

    ./int_remover -i $(IF_NAME)

Where ``$(IF_NAME)`` is the name of the interface to attach the XDP program to.
If you don't know what the name of the interfaces on your system are,
you can check them by running the following command:

.. code:: bash

    ip link list

Once the XDP program is fully attached,
any traffic ingested by the interface will have its INT data removed,
and the removed INT data will be printed to standard out.
To detach the XDP program send a keyboard interrupt (``Ctrl`` + ``C``),
to the program.

For more details on execution, see the help provided with the following command.

.. code:: bash

    ./int_remover --help
