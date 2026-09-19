# Windows client acceptance continuation

This file is retained only so old links do not redirect engineers to the
deleted P-256/public-report design. Continue Windows work from
[the rebuild entry](rebuild/README.md),
[the client runtime model](rebuild/client-runtime-model.md), and
[the enrollment endpoint model](rebuild/enrollment-endpoint-model.md).

Acceptance must follow the normal Misaka UI, private claim/resume wire,
DPAPI-protected profile, certified runtime, selector readback, real TCP/TLS and
UDP/DNS results, private signed report, and control/UI readback. Do not restore
public enrollment/report/config/pull routes, Agent scheduling, sample windows,
P-256 certificate identities, or v1 fallback.
