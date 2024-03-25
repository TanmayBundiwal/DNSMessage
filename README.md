# DNSMessage

DNSMessage is a sophisticated Java-based DNS resolver that efficiently crafts and sends DNS queries in a binary format. Designed for detailed interaction with DNS protocols, this tool parses and interprets responses from DNS servers, providing a deep understanding of network communications at the DNS level.

## Key Features

- **Binary DNS Query Crafting**: Utilizes Java's ByteBuffer for efficient construction of DNS queries in binary format.
- **Domain Name Compression**: Implements domain name compression in DNS messages to optimize query and response sizes.
- **Handling Various Record Types**: Capable of handling multiple DNS record types, including A, AAAA, MX, NS, and more.
- **Resolver Functionality**: Acts as a resolver that sends crafted queries to DNS servers and interprets the responses, rather than functioning as a DNS server itself.
- **Support for Recursive and Iterative Queries**: Capable of handling both recursive and iterative query modes, depending on the DNS server configuration.

## Getting Started

### Prerequisites

- Java Runtime Environment (JRE) or Java Development Kit (JDK)
- Basic knowledge of DNS protocols

### Installation

1. Clone the repository or download the source code.
2. Navigate to the project directory.

### Running the Project

Execute the project using the Makefile:

```bash
make run
```

This command compiles the Java source files and executes the DNSMessage application.

## Usage

DNSMessage can be used to send DNS queries for specific domain names and request different types of DNS records. It demonstrates how DNS queries are constructed, sent, and how responses are interpreted.
