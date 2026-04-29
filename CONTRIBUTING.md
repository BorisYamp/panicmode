# Contributing to PanicMode

Thanks for considering a contribution. Bugs, feature ideas, doc fixes, and PRs are all welcome — preferably in that order, since the smallest contribution that lands a real improvement is usually the one that starts with an issue.

---

## Reporting a bug

Before filing, check that you can reproduce against the current `main`. PanicMode v0.1.0 went through a 4-round hardening pass and many "obvious" bugs of the period are already fixed (see [CHANGELOG.md](CHANGELOG.md)).

Open the issue with at minimum:

- Linux distro + kernel + systemd version (`uname -srv && systemctl --version | head -1`)
- PanicMode version (`panicmode --validate /etc/panicmode/config.yaml` prints OK on success; the binary version is in `Cargo.toml` at build time)
- The relevant section of `journalctl -u panicmode --since "10 minutes ago" --no-pager`
- Your `config.yaml` with secrets redacted (`bot_token`, `webhook_url`, `smtp_password`, etc.)
- What you expected to happen vs what actually happened

If the bug is security-sensitive (could allow privilege escalation, denial of remote management, etc.), don't open a public issue — email the maintainer first or flag it via GitHub's private security report flow.

---

## Suggesting a feature

Open an issue describing **what problem the feature solves**, not just the solution shape. PanicMode is small on purpose; a feature that requires a heavyweight dependency, a new daemon, or a new attack surface needs to clear a high bar.

The [Roadmap section in README](README.md#roadmap) has work that's been triaged and is open for grabs. Pinning a "👋 picked up by @you" comment there is enough to claim it.

---

## Submitting a PR

1. **Open an issue first** if the change is bigger than a typo or a one-line fix. A 5-line "this is the approach I'm thinking" comment saves a lot of "please redo this differently" later.

2. **One concern per PR.** Mixing a bug fix with a refactor and a new feature makes review hard and rollback harder.

3. **Run the full test suite locally**:

   ```bash
   cargo test --release
   ```

   124 tests should pass on a Linux host. A couple of the integration tests assume `journalctl` and `systemctl` exist (Ubuntu/Debian/RHEL family) — those that can't probe gracefully return defaults rather than fail.

4. **Build clean**:

   ```bash
   cargo build --release
   cargo clippy -- -D warnings
   ```

5. **Test against a real config** if your change touches a monitor, action, or alert channel:

   ```bash
   sudo cp target/release/panicmode /usr/local/bin/
   panicmode --validate /etc/panicmode/config.yaml
   sudo systemctl restart panicmode
   journalctl -u panicmode -f
   ```

   The flow that catches the most regressions: pick a monitor, lower its threshold so it fires almost immediately, induce the condition (`stress-ng`, `fallocate`, `logger -p auth.warn`, etc.), and watch the incident → action → alert cycle in `journalctl`.

6. **Match the existing commit message style**: `area(scope): short imperative summary`, then a paragraph explaining the **why**, then `Refs: #N` if it relates to an open issue. Per-bug commits are preferred over big monolithic ones — they're nicer to bisect and revert.

7. **Don't reformat the world**: avoid `rustfmt`-on-everything in the same PR as a behavioral change. If you want a formatting pass, do it separately so reviewers can read the diff.

---

## Local testing notes

- A fresh Ubuntu 24.04 / Debian 12 VPS is the reference target. Other distros work; `examples/block_ip.sh` assumes `/usr/sbin/iptables` and `/usr/sbin/ip6tables` exist at those exact paths — adjust if your distro puts them elsewhere.
- The systemd unit (`panicmode.service`) is hardened (`ReadOnlyPaths=/`, `RestrictAddressFamilies`, `SystemCallFilter`). When adding a feature that needs a new syscall or filesystem write, expect to update the unit too — silent failure under hardening is a common pitfall.
- The reference iptables-based `block_ip.sh` is idempotent (`-C` before `-I`); please keep that property if you submit a variant for `nftables`/`ufw`/`firewalld`.
- For changes to the auth monitor, please keep the journald-with-`_SYSTEMD_UNIT=ssh.service` source. Reading `/var/log/auth.log` directly is a known security regression (any local non-root user can spoof entries via `logger`).

---

## Code of conduct

Be kind, be specific, and assume the other party is doing their best with limited information. The full Contributor Covenant text is what we'd reach for if we ever needed it; until then, just don't be a jerk.

---

## License

By submitting a contribution, you agree that it will be dual-licensed under the project's [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licenses (recipient's choice), matching the rest of the codebase.
