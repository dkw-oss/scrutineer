# Podman & rootless runtime — security model

Scrutineer runs each scan's untrusted workload — the cloned repository plus
`claude -p --permission-mode bypassPermissions` and the analysis tools — inside
an ephemeral container. The runtime is selectable with `--runtime docker|podman`
(default `docker`; see [Podman (rootless)](../README.md#podman-rootless) in the
README for setup).

This is a companion to [threatmodel.md](../threatmodel.md): it covers what the
**podman / rootless** runtime changes about the security posture, and — the main
point — the gaps it does **not** close. It assumes the threat model's framing,
in particular T1 (RCE via a hostile repository), T12 (runtime access), and T13
(runner egress).

## Where the runtime sits

scrutineer runs as a host process and execs the runtime directly; it does **not**
mount a runtime socket (threatmodel T12, "run scrutineer as a host process").
The runtime's only job is to confine boundary 3 of the threat model — the
untrusted checkout and the model/tools that parse it. Choosing docker vs podman
changes *how strongly* that boundary holds, not what runs inside it.

Three configurations exist, weakest to strongest:

- `--no-docker` — no container; the workload runs on the host as the operator.
  Least isolation (unchanged, out of scope for this document).
- `--runtime docker` *(default)* or rootful podman — container-root maps to a
  uid the daemon runs as; the daemon/socket is root-equivalent.
- `--runtime podman` **rootless** — daemonless, and container-root maps to an
  unprivileged host sub-uid.

## Properties rootless podman adds

- **Runtime access is not root-equivalent.** Rootless podman is daemonless;
  there is no root-owned `docker.sock`. A compromise of the scrutineer process
  cannot trivially become host-root through the runtime — the residual concern
  in T12.
- **Container-root is an unprivileged sub-uid.** In the rootless user namespace,
  uid 0 inside the container maps to a subordinate uid on the host. An escape
  from the scan container (the T1 endgame) lands unprivileged, not near-root.
  This is the largest blast-radius reduction.
- **The workspace stays operator-owned via `--userns=keep-id`.** The container
  process is mapped back to the invoking user's uid, so the `/work` output and
  the `/claude-config` resume store are owned by the operator — not root, not an
  opaque sub-uid. Without keep-id, rootless bind-mount writes land under a
  remapped sub-uid and break the scan; the runner injects it only for rootless
  podman (docker and rootful podman already run as the host uid).

## Network isolation and hardened mode

Default (cooperative) mode is unchanged from the docker path (T13): the container
reaches the network through an allowlisting host proxy via `HTTPS_PROXY` /
`HTTP_PROXY`, but a workload that ignores those variables is not blocked at the
network layer.

`--hardened` is the enforced mode: each scan gets a dedicated `--internal`
network so a workload ignoring the proxy has no route out, and concurrent scans
cannot reach each other. On docker's bridge driver this property is well
understood and trusted. **On podman it is verified, not assumed**, because
rootless `--internal` semantics vary across network backends (pasta,
slirp4netns, netavark) and versions. Before each hardened scan two throwaway
containers run on the actual per-scan network:

1. **Egress is blocked** — with no proxy environment, an attempt to reach a
   *literal* routable IP must fail. A literal address (not a hostname) is used
   deliberately: DNS is also cut on `--internal`, so a hostname target would
   fail for the wrong reason and read as a false pass.
2. **The host proxy is reachable** — a connection to the proxy through the
   host-gateway alias, wired exactly as the real run wires it, must succeed.

The check is **fail-closed**: if either property cannot be confirmed — including
a probe that cannot even execute (e.g. no `curl` in a custom runner image) — the
scan is **refused** rather than run under a weaker sandbox. It is gated to
podman, so it covers both rootless and rootful podman; docker keeps its trusted
path and pays no probe cost.

## Gaps and residual risks

These are **not** addressed by the podman / rootless runtime and remain open:

1. **Default-mode egress is cooperative, not enforced.** Only `--hardened`
   blocks a proxy-ignoring workload (pre-existing T13 residual; both runtimes).
2. **keep-id widens the user namespace to include the operator's uid.** A
   container escape that pivots to that uid could touch host files owned by the
   operator *that are reachable through the bind mounts*. Far better than
   rootful, but not zero — run scrutineer as a dedicated low-privilege user.
3. **Host-gateway reachability is environment-dependent.** On some rootless
   network configurations the container may not reach a host-bound proxy.
   Hardened mode then correctly *refuses* (a denial of function, not a hole);
   default mode simply loses egress. Not auto-remediated.
4. **podman < 4.7 is warned, not gated.** `--add-host …:host-gateway` is
   unsupported below 4.7, so egress breaks; startup logs a warning (hardened
   additionally catches it via verification) but does not block.
5. **Profile base-image freshness degrades without `skopeo`.** podman has no
   `buildx imagetools`; without skopeo a moved `:latest` runner tag won't
   trigger a per-ecosystem profile rebuild (the cache keys on the ref string),
   so a stale profile image may be reused until pruned. Not a code-execution
   risk (the base is still the pinned ref), but a freshness gap.
6. **Hardened verification needs `curl` in the runner image.** A custom
   `--runner-image` without curl makes verification fail closed (safe) but
   unusable.
7. **Verification is point-in-time.** It proves isolation at scan start, not
   continuously; it does not detect a mid-scan network reconfiguration. The
   per-scan network is ephemeral and created by scrutineer, but this is a TOCTOU
   window against a host-local privileged actor (who already out-ranks the
   sandbox).
8. **No runner resource limits under either runtime.** No `--memory`,
   `--pids-limit`, or CPU caps are set, so a hostile repo can still attempt local
   resource exhaustion (threatmodel T9, open). Under rootless podman, cgroup
   limits additionally require cgroup v2 delegation, which scrutineer neither
   requires nor configures.
9. **User-namespace / sub-id exhaustion is not pre-checked.** Many concurrent
   rootless containers consume userns and subuid ranges; if exhausted, the
   container fails to start and the scan fails.
10. **Kernel attack surface is shared.** Like docker, rootless podman shares the
    host kernel; user namespaces reduce but do not eliminate kernel-LPE surface.
    For stronger isolation, a VM-backed or syscall-filtering runtime (sysbox,
    gVisor) remains the option noted in T12 — not implemented.
11. **seccomp/AppArmor parity, not improvement.** The runtime's default profiles
    are used under both engines; no custom profile is added.
12. **Supply chain is unchanged.** podman pulls the same GHCR runner image;
    threatmodel T11 carries over verbatim.

## Operational guidance

- For untrusted inputs, prefer `--runtime podman --hardened`: a
  non-root-equivalent runtime plus verified network isolation is the strongest
  configuration this tool offers.
- Run scrutineer as a **dedicated low-privilege OS user** to bound gap #2.
- Ensure **podman ≥ 4.7** and a configured `/etc/subuid` / `/etc/subgid` range
  for that user (`podman system migrate` applies changes). Install **skopeo** if
  you rely on per-ecosystem profiles staying current.
- Treat the open threatmodel residuals (T9 resource caps, T13 cooperative
  default) as still applying under podman.

## See also

- [threatmodel.md](../threatmodel.md) — full system threat model (T1, T12, T13).
- [README: Podman (rootless)](../README.md#podman-rootless) — setup and requirements.
