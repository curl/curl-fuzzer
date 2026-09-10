# TLV wire format

A legacy testcase is a sequence of binary type-length-value (TLV) records.
There is no file header or record count. Each record starts with this six-byte
header:

| Offset |           Size | Field  | Encoding                                    |
|-------:|---------------:|--------|---------------------------------------------|
|      0 |        2 bytes | Type   | Unsigned 16-bit integer, network byte order |
|      2 |        4 bytes | Length | Unsigned 32-bit integer, network byte order |
|      6 | `Length` bytes | Value  | Meaning depends on the type                 |

For example, the `CURLOPT_URL` value `http://127.0.0.1` is encoded as:

```text
00 01  00 00 00 10  68 74 74 70 3a 2f 2f 31
                        32 37 2e 30 2e 30 2e 31
type   length = 16      value
```

The C parser uses `to_u16()` and `to_u32()` to decode the fields. The Python
encoder and decoder use the equivalent `!H` and `!L` formats in
`src/curl_fuzzer_tools/corpus.py`.

## Value forms

The type number determines how the value is interpreted:

- The Python encoder writes string option values as UTF-8 without a terminating
  NUL. The harness copies arbitrary value bytes and appends a terminator before
  calling libcurl, so a mutated value may still contain embedded NUL bytes.
- Integer option records contain exactly one four-byte unsigned integer in
  network byte order. `FU32TLV` passes it as a `long`; `FU32TLV_OFF_T` passes
  it as a `curl_off_t`.
- Response and upload records contain uninterpreted bytes. Response 0 is sent
  when the simulated socket opens; later response records are sent as curl
  produces requests. A small second set of response types serves protocols
  such as FTP that can open another connection.
- A MIME-part record (type 13) contains a nested TLV stream. Only the MIME name
  and data records (types 14 and 15) are valid in that nested stream.
- Header, mail-recipient, and MIME-part records may be repeated. Most curl
  option records are singletons.

The authoritative C type IDs are the `TLV_TYPE_*` definitions in
`curl_fuzzer.h`. `BaseType` and `BaseType.TYPEMAP` in
`src/curl_fuzzer_tools/corpus.py` provide the corresponding Python IDs and
human-readable decoder names. Avoid copying the full list into documentation.
`tests/test_tlv_constants_sync.py` checks that the C and Python numeric ID sets
remain unique and synchronized.

## Parser behavior

An input shorter than six bytes cannot contain a record and returns without a
transfer. For each record, a declared value that extends beyond the input is a
size error, and an unknown top-level type is rejected. Integer cases also
reject values whose length is not four.

HSTS type 51 remains declared for corpus compatibility but has no enabled
parser case. `POSTFIELDSIZE` (212) and `POSTFIELDSIZE_LARGE` (322) are likewise
declared but deliberately disabled to avoid easy API misuse. The
structure-aware mutation lane excludes all three, although its periodic raw
byte mutation can still produce any bit pattern. MIME name and data (14 and
15) are valid only inside a MIME-part record, not at the top level.

The harness treats fewer than six bytes left after a complete record as the end
of the stream. The custom mutator deliberately matches that historical
behavior, although generated corpora should end exactly on a record boundary.

The structure-aware mutator applies stricter rules than the byte parser before
performing record-level edits: it accepts eligible top-level IDs, valid
four-byte integers, valid nested MIME framing, and no duplicate scalar records.
This distinction lets the raw mutation lane continue to test parser behavior
while ordinary mutations spend more executions inside libcurl.

Continue with [Working with corpora](corpora.md) to inspect or create this
format.
