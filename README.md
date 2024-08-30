# :boat: Voyage

Voyage is a Rust-based network probing tool that leverages the Diamond Miner algorithm to perform traceroute operations. It supports multiple output formats including Atlas, Iris, MetaTrace, and Scamper wart (binary). The tool is designed to be efficient and configurable, allowing users to specify various parameters such as TTL range, ports, confidence level, and probing rate.

:warning: This is a research project and is still under development. Use it at your own risk.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Example](#example)
- [Estimate Successors Option](#estimate-successors-option)
- [Logging](#logging)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)

## Prerequisites

Before you can build and run Voyage, you need to have the following dependencies installed:

- **Rust and Cargo**: You can install Rust and Cargo by following the instructions on the [official Rust website](https://www.rust-lang.org/tools/install).
- **libpcap**: This library is required for packet capturing. You can install it using your package manager:

  - **Ubuntu/Debian**:
    ```sh
    sudo apt-get update
    sudo apt-get install libpcap-dev
    ```

  - **Fedora**:
    ```sh
    sudo dnf install libpcap-devel
    ```

  - **macOS**:
    ```sh
    brew install libpcap
    ```

  - **Rocky Linux 9**:
    [Managing Repositories in Rocky Linux](https://wiki.rockylinux.org/rocky/repo/)
    ```sh
    sudo dnf config-manager --set-enabled crb
    ```

    ```sh
    sudo dnf install libpcap-devel
    ```

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/teo-lohrer-su/voyage.git
    cd voyage
    ```

2. **Build the project**:
    ```sh
    cargo build --release
    ```

3. **Run the executable**:
    ```sh
    ./target/release/voyage --help
    ```

## Usage

Voyage provides a variety of command-line options to configure the traceroute operation. Below are the available options:

```sh
Usage: voyage [OPTIONS] --dst-addr <DST_ADDR>

Options:
  -d, --dst-addr <DST_ADDR>            Destination IP address
      --min-ttl <MIN_TTL>              Minimum TTL [default: 1]
      --max-ttl <MAX_TTL>              Maximum TTL [default: 32]
      --src-port <SRC_PORT>            Source port [default: 24000]
      --dst-port <DST_PORT>            Destination port [default: 33434]
  -c, --confidence <CONFIDENCE>        Confidence level [default: 99.0]
  -m, --max-round <MAX_ROUND>          Maximum number of rounds [default: 100]
  -e, --estimate-successors            Estimate successors [default: false]
  -o, --output-format <OUTPUT_FORMAT>  Output format [default: atlas] [possible values: atlas, iris, flat, internal, scamper, quiet]
      --receiver-wait-time <RECEIVER_WAIT_TIME>
                                       Receiver wait time in seconds [default: 1]
      --probing-rate <PROBING_RATE>    Probing rate in packets per second [default: 100]
  -p, --protocol <PROTOCOL>            Protocol to use (ICMP or UDP) [default: icmp] [possible values: icmp, udp]
  -i, --interface <INTERFACE>          Network interface to use
  -h, --help                           Print help information
  -V, --version                        Print version information
```

### Example

To run a traceroute to `8.8.8.8` with default settings:

```sh
./target/release/voyage --dst-addr 8.8.8.8
```

To run a traceroute to `8.8.8.8` with a custom TTL range and output format:

```sh
./target/release/voyage --dst-addr 8.8.8.8 --min-ttl 5 --max-ttl 20 --output-format flat
```

To run a traceroute to `8.8.8.8` using UDP protocol and a specific network interface:

```sh
./target/release/voyage --dst-addr 8.8.8.8 --protocol udp --interface eth0
```

## Estimate Successors Option

The `--estimate-successors` option attempts to guess the number of successors of a node based on the number of successors discovered so far and the number of probes sent. This estimation is made using a statistical approach involving Stirling numbers of the second kind. The algorithm calculates the probability of discovering a certain number of interfaces after a given number of probes and uses this to estimate the total number of interfaces.

The estimation process involves:

1. **Stirling Ratios**: See [Stirling numbers of the second kind](https://en.wikipedia.org/wiki/Stirling_numbers_of_the_second_kind) and the [stirling_numbers crate](https://docs.rs/stirling_numbers/latest/stirling_numbers/fn.stirling2_ratio_table.html).

2. **Event Probability**: The probability of finding exactly $k$ interfaces after $n$ probes given $K$ total interfaces. This is calculated as:

   $$\mathbb{P}[Y_{n, K} = k] = \frac{1}{K^n}\cdot\binom{K}{k}\cdot {n\brace k}\cdot k!$$

   where $\binom{K}{k}$ is the binomial coefficient, and ${n\brace k}$ is the Stirling number of the second kind.

3. **Total Interfaces Estimation**: Using the event probability, we can find the most *likely* number of interfaces $K$ given the number of probes $n$ and the number of interfaces discovered so far $k$.

This option can help optimize the probing process by reducing the number of probing *rounds*, at the cost of marginally more probes, thus potentially making the traceroute operation more efficient when many load balancers exhibit large numbers of outgoing interfaces.

## Logging

Voyage uses the `env_logger` crate for logging. You can control the log level by setting the `RUST_LOG` environment variable. For example:

```sh
RUST_LOG=info ./target/release/voyage --dst-addr 8.8.8.8
```

The `debug` log level provides detailed information about the probing process, including the number of interfaces discovered, the number of probes sent, the discovered links, *etc.*

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on the [GitHub repository](https://github.com/teo-lohrer-su/voyage).

### TODO

- [ ] Traceroute single path output format
- [ ] DNS resolution
- [ ] ICMPv6 support
- [ ] Port the topological tests from the Python prototype

## Acknowledgements

We would like to acknowledge the contributions and support from the following:

- **Dioptra**: [Dioptra Homepage](https://dioptra.io)
- **Maxime Mouchet**: For the development of the [pantrace](https://crates.io/crates/pantrace) and [caracat](https://crates.io/crates/caracat) crates.
- **fast-mda-traceroute**: A Python project that prototyped most of this tool. [fast-mda-traceroute](https://github.com/dioptra-io/fast-mda-traceroute)
