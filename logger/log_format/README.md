# Tempesta event-log formatter

`eventlog_format` is a ClickHouse executable user-defined function (UDF). It
converts the binary `event_body` written by `tfw_logger` into the human-readable
message defined for its `event_type` in `fw/event_types.h`.

The UDF has this SQL signature:

```sql
eventlog_format(event_type UInt16, event_body String) -> String
```

It is intended for the `security_dos_log` and `security_web_attack_log` tables
created by the access-log plugin. It is not a conventional command-line tool:
ClickHouse communicates with it over standard input and output using the
`RowBinary` format.

## Install in ClickHouse

For a self-hosted ClickHouse installation using the default paths, copy the
executable into the `user_scripts` directory and the function definition into
the server configuration directory:

```sh
sudo install logger/log_format/eventlog_format \
    /var/lib/clickhouse/user_scripts/eventlog_format
sudo install logger/log_format/log_format_function.xml \
    /etc/clickhouse-server/log_format_function.xml
sudo systemctl restart clickhouse-server
```

If `user_scripts_path` or `user_defined_executable_functions_config` is
customized in the ClickHouse server configuration, use those locations
instead.

## Verify the installation

Check that ClickHouse loaded the function:

```sh
clickhouse-client --query \
    "SELECT name FROM system.functions WHERE name = 'eventlog_format'"
```

The result should contain `eventlog_format`. If it does not, inspect the
ClickHouse server log for XML-loading, path, ownership, or execute-permission
errors.

## Query formatted events

Format DoS events:

```sql
SELECT
    timestamp,
    client_address,
    client_port,
    local_port,
    eventlog_format(event_type, event_body) AS event,
    ip_block,
    dropped_events
FROM security_dos_log
ORDER BY timestamp DESC;
```

Format web-attack events:

```sql
SELECT
    timestamp,
    client_address,
    client_port,
    local_port,
    eventlog_format(event_type, event_body) AS event,
    ip_block,
    dropped_events
FROM security_web_attack_log
ORDER BY timestamp DESC;
```

If `tfw_logger` is configured with different table or database names, qualify
or replace the names in these examples accordingly.

Malformed input, an unknown event type, or an event body that does not match
the expected binary layout is returned as:

```text
<broken record>
```

## Keep the formatter in sync

The executable compiles in the event definitions from `fw/event_types.h` and
decodes the binary layout produced by the Tempesta kernel module. Rebuild and
reinstall it whenever those definitions or the event-log binary format change.
The formatter, Tempesta FW, and `tfw_logger` should come from the same source
revision.

