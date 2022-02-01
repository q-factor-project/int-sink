# INT-Sink

The main purpose of this project is to remove INT metadata from incoming packets,
and make the metadata accessible to userspace applications.
To do so, an XDP program is attached to the network interface
and parses all incoming packets for INT metadata.
INT metadata is then sent to userspace using
a perf event array.
Additional maps are also provided to provide additional control,
and information about flows.

# Building

In order to build and run this application,
the following packages should be installed:

 - clang 12.0+
 - bpftool v5.12.0+
 - GNU make
 - iproute2

Before you can get started building,
make sure that the libbpf submodule has been pulled.
To do so, run the following command:

```bash
git submodule update --init
```

Once all the prerequsites have been met,
from the project home directory
run the following command to build:

```bash
make
```

Once the project has been built,
the INT-sink will be available
as `int-sink+filter.bpf.o` in the `src/xdp/`
directory.

# Running the INT-sink application

Interacting with the BPF subsystem
requires `root` priviledges,
so all commands in this section should
be run as `root`.
To use the INT-sink application,
it must be loaded into the kernel,
then attached to the appropriate interface.

To load the application onto the kernel,
run the following command:

```bash
bpftool prog load int-sink+filter.bpf.o <BPF-FS-PIN-LOCATION> pinmaps <BPF-FS-MAP-PIN-LOCATION>
```

`<BPF-FS-PIN-LOCATION>` should be replaced with a path to a file
to be created in the bpf filesystem.
This file will be a reference to the program.
This reference will later be used to attach the program.
`<BPF-FS-MAP-PIN-LOCATION>` should be replaced with a path
to a directory to be created in the bpf filesystem.
This directory will contain references to all the maps of the program.
These references will later be used to receive data from the,
and adjust the behaviour of the program.

Additinal parameters for the program load command exist,
such as `dev <DEV-NAME>` which will offload
the program onto the hardware interface `<DEV-NAME>`.
Attempting to load the program into offload mode
will likely result in `bpftool` printing an error/warning
about map BTF info, which you can ignore.

After the program has been loaded onto the kernel,
the next step is to attach it to a device.
Attaching is NOT offloading.
To attach the loaded program to the device,
run the following command:

```bash
ip link set dev <DEV-NAME> <XDP-MODE> pinned <BPF-FS-PIN-LOCATION>
```

`<DEV-NAME>` should be replaced with the interface to attach to.
`<XDP-MODE>` should be one of either `xdpoffload`, `xdpdrv`,
or `xdpgeneric`, which specify which mode the XDP
program should be attached as.
`<BPF-FS-PIN-LOCATION>` should be replaced with the reference
to the program in the bpf file system.

Once the program is attached it will be running
on the interface.

# Configuration

The int sink application has several configurable parameters.
By default, the program will pass all int metadata received
to the `perf_output_map`.
However, it may be preferable that we only pass
metadata for specific flows to the output map,
or that the flow meets some threshold.
To do so, one can add entries to the
`flow_threshold_map` and the `hop_threshold_map`.
If no entry exists in these maps,
the INT metadata will automatically be passed
to the output map.

Updating _can_ be done with `bpftool`,
however it is suggested that users develop
their own programs to automate the process,
and customize the solution to their needs.
To do so, information about the map definitions
is required.
The following code is the definitions used for the
threshold maps:

```c
struct flow_key {
    __u32 switch_id;
    __u16 egress_port;
    __u16 vlan_id;
};

struct hop_key {
    struct flow_key flow_key;
    __u32 hop_index;
};

struct flow_thresholds {
    __u32 hop_latency_threshold;
    __u32 hop_latency_delta;
    __u32 sink_time_threshold;
    __u32 sink_time_delta;
    __u32 total_hops;
};

struct hop_thresholds {
    __u32 hop_latency_threshold;
    __u32 hop_latency_delta;
    __u32 queue_occupancy_threshold;
    __u32 queue_occupancy_delta;
    __u32 switch_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct flow_key);
    __type(value, struct flow_thresholds);
} flow_thresholds_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct hop_key);
    __type(value, struct hop_thresholds);
} hop_thresholds_map SEC(".maps");
```

# Output

For output, the int sink application has sets of counters,
for counting the amount of packets received and the total bytes
received.
The counters are divided into two sets,
a set of general counters in the `counters_map`,
and a set of per flow counters in `flow_counters_map`.
The `counters_map` has two entries,
entry `0` being for all packets, and
entry `1` being for all packets with INT data.
The `flow_counters_map` is supposed to contain
entries for each INT flow, and must be updated from
userspace to have entries.
The following are the definitions used for
the counter maps:

```c
struct flow_key {
    __u32 switch_id;
    __u16 egress_port;
    __u16 vlan_id;
};

struct counter_set {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct flow_key);
    __type(value, struct counter_set);
} flow_counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct counter_set);
} counters_map SEC(".maps");
```

The final and most important piece is the perf output map.
Output to this map shall be formated as a flow key +
number of hops, followed by an array of INT metadata
entries. The following definitions represent
the expected output.

```
struct flow_key {
    __u32 switch_id;
    __u16 egress_port;
    __u16 vlan_id;
};

struct hop_key {
    struct flow_key flow_key;
    __u32 hop_index; // Hop index used to count number of hops
};

struct int_hop_metadata {
    __be32 switch_id;
    __be16 ingress_port_id;
    __be16 egress_port_id;
    __be32 hop_latency;
    __be32 queue_info;
    __be32 ingress_time;
    __be32 egress_time;
};

struct perf_output_template { //This is only a template, not usable as C code
    struct hop_key event_key;
    struct int_hop_metadata hops[];
    // Potentially extra data afterwards
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_output_map SEC(".maps");
```


