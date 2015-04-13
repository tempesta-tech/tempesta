## Tempesta Language

### Description

The **Tempesta Language (TL)** is a a small domain-specific programming language
for **Tempesta FW**. It's designed to be used to define Tempesta FW
configuration, program dynamic multi-layer network filtering rules and process
HTTP requests and responses in various ways.

TL scripts are compiled to native machine code. The compiler front-end is
user-space application, while code generation and linkage are performed in
kernel space.


### Syntax

The TL syntax is very close to Perl to be as convenient for text processing as
possible.
