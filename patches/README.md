# werift 0.24.4 DTLS receiving repair

`werift@0.24.4.patch` applies to the exact version in `package.json` and
`bun.lock`. Run `bun install --frozen-lockfile` in the daemon package before
building. The standard compiler rejects an unpatched dependency tree.

The patch uses one bounded receiver shared by the main ESM and CommonJS
entrypoints. It reassembles fragments by message sequence, rejects conflicting
overlaps/metadata, and dispatches complete handshake messages in sequence.
Retained payload is limited to 64 messages / 128 KiB, plus at most 128 KiB of
coverage bookkeeping. Overflow is terminal. Close clears the receiver and
cancels flight retry timers. Duplicate final-flight recovery remains supported.
Certificate, cipher, fingerprint and authorization checks are unchanged.

The helper lives in the existing fragment module because Bun 1.3.14 failed to
apply a patch adding a new nested file (`EACCES: mkdir`). A clean installation
of this existing-file patch is qualified; no install bypass is required.

Regressions:

```sh
bun test src/rtc-dtls.test.ts src/rtc-close.test.ts
bun repair/rtc-dtls-runtime-test.ts receipt.json reorder-certificate
bun repair/rtc-dtls-runtime-test.ts receipt.json fragment-client
bun repair/rtc-dtls-runtime-test.ts receipt.json cancel-missing
bun repair/rtc-reset-loss-test.ts receipt.json drop-first-burst
```

Other runtime modes cover control, reordered key exchange, server fragments,
both lost Finished flights, duplicate client flights and wrong fingerprints.
`drop-all` qualifies finite local reset cleanup, not remote delivery.

The application close helper also waits for outstanding SCTP resets before
tearing down ICE. Its deadline permits one current reset RTO plus 500 ms,
bounded to 1–4 seconds. The external test's five-second deadline is unchanged.

Protocol basis: [RFC 6347 sections 4.2.2–4.2.3](https://www.rfc-editor.org/rfc/rfc6347.html#section-4.2.2).
Remove the compatibility patch only after an upstream version passes the same
fault, authentication, retransmission and cleanup matrix on both entrypoints.
