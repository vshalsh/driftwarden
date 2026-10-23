# 12. Store names as Unicode — “café” stays “café”

## Status

Accepted ✅

## Context

Customer names such as “Zoë”, “Łukasz” and “渡辺” were mangled by ASCII-only columns.

## Decision

All text columns use **UTF-8** and names are stored *exactly* as entered — we don’t
“normalise” them to ASCII. Comparison uses Unicode NFC form; the API’s “name” field is
never transliterated.

## Consequences

Sorting depends on the database collation (`und-x-icu`).
