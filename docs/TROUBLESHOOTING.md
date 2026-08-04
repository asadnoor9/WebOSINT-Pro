# Troubleshooting

- [The `webosint` command runs the wrong program](#the-webosint-command-runs-the-wrong-program)
- [Tests fail after upgrading in place](#tests-fail-after-upgrading-in-place)
- [`pip install -e '.[all]'` fails with no matches found](#pip-install--e-all-fails-with-no-matches-found)
- [`command not found` when running a script with sudo](#command-not-found-when-running-a-script-with-sudo)
- [`ufw: command not found`](#ufw-command-not-found)
- [The dashboard is not reachable from another machine](#the-dashboard-is-not-reachable-from-another-machine)
- [The service crash-loops with a read-only filesystem error](#the-service-crash-loops-with-a-read-only-filesystem-error)
- [`webosint doctor` exits non-zero](#webosint-doctor-exits-non-zero)
- [A scan takes far too long](#a-scan-takes-far-too-long)
- [PDF or Word export fails](#pdf-or-word-export-fails)
- [Port scanning reports an error](#port-scanning-reports-an-error)
- [A scan is refused before it starts](#a-scan-is-refused-before-it-starts)

---

## The `webosint` command runs the wrong program

**Symptom:** `webosint doctor` prints `error: unrecognized arguments: doctor`
and a usage line beginning `usage: webosint [-h] [-t TARGET] ...`.

**Cause:** that is the standalone legacy scanner, not the packaged CLI. Older
releases of `install.sh` wrote a wrapper to `/usr/local/bin/webosint` that
shadows the console script pip installs into your virtual environment.

**Fix:**

```bash
type -a webosint                    # shows both paths
sudo rm /usr/local/bin/webosint
hash -r                             # clear bash's cached lookup
which webosint                      # must be .../venv/bin/webosint
```

`hash -r` is not optional — bash keeps serving the deleted path for the rest of
the session without it.

Current releases install the legacy wrapper as `webosint-scan` instead, and
remove the shadowing one if they find it.

---

## Tests fail after upgrading in place

**Symptom:** failures such as
`TypeError: SafetyController.__init__() got an unexpected keyword argument 'open_target'`
or `JSONReport.__init__() got an unexpected keyword argument 'redact'`, while
the rest of the suite passes.

**Cause:** unpacking a new release over an existing directory adds and
overwrites files, but never deletes files that were removed upstream. Those
failures come from stale test files exercising APIs that no longer exist.

**Fix — clean reinstall:**

```bash
cd ..
mv webosint-pro webosint-pro.old
unzip -q webosint-pro.zip
cd webosint-pro
python3 -m venv venv && source venv/bin/activate
pip install -e '.[all]'
pytest tests -q
```

Your reports, database and configuration live in `~/.webosint`, outside the
repository, so they survive this. Stale *source* files can shadow new code
silently rather than failing loudly, which is why a clean directory beats
deleting individual files.

---

## `pip install -e '.[all]'` fails with no matches found

You are on zsh and dropped the quotes. Square brackets are a glob there:

```bash
pip install -e '.[all]'     # correct
pip install -e .\[all\]     # also works
```

---

## `command not found` when running a script with sudo

**Symptom:** `sudo: ./scripts/install-service.sh: command not found`

The file is missing its executable bit; sudo reports that misleadingly.

```bash
chmod +x scripts/*.sh install.sh
```

---

## `ufw: command not found`

ufw simply is not installed — unrelated to WebOSINT Pro.

```bash
sudo apt install ufw
sudo ufw allow from 192.0.2.0/24 to any port 8000 proto tcp
sudo ufw enable
```

Substitute your own subnet. Note what "no firewall" means: if you installed the
service with `--lan` and without `--auth`, anyone who can route to port 8000 can
launch scans and read every stored report.

---

## The dashboard is not reachable from another machine

Work through these in order:

1. **Binding.** `--host 0.0.0.0` alone is deliberately not enough; it falls back
   to loopback. You also need `--allow-remote`, or install the service with
   `--lan`, which adds it for you.
2. **Confirm what it is actually listening on**, and wait a couple of seconds
   after a restart before checking — checking immediately shows nothing:
   ```bash
   sleep 3; ss -ltnp | grep 8000
   ```
   `0.0.0.0:8000` is correct. `127.0.0.1:8000` means it is still loopback-only.
3. **Firewall.** Allow the port from your subnet only.
4. **Right address.** Use the machine's LAN address from `ip -4 addr`.

---

## The service crash-loops with a read-only filesystem error

**Symptom:** `OSError: [Errno 30] Read-only file system` naming a path inside
the repository, or systemd reporting `status=226/NAMESPACE`.

**Cause:** the unit's sandboxing cannot create its runtime directory — typically
`ProtectHome` blocking a home-directory install, or a `ReadWritePaths` entry
that does not exist yet.

**Fix:** reinstall the service so the shipped unit template is regenerated:

```bash
sudo ./scripts/install-service.sh --uninstall
sudo -E ./scripts/install-service.sh --lan
```

If you hand-edited the unit, remove your override first — `sudo systemctl revert
webosint`. Note that setting `ProtectHome=` to an empty value does **not**
disable the protection; it must be `ProtectHome=no`.

---

## `webosint doctor` exits non-zero

Only blocking problems affect the exit code: an unsupported Python version or an
unwritable runtime directory. Warnings such as `Start on boot: not enabled` or a
missing optional tool are informational and do not.

Run `webosint doctor --json` for machine-readable `blocking` and `warnings`
lists.

---

## A scan takes far too long

First, check which modules actually ran. The engine fingerprints the target and
skips inapplicable families automatically; if a static site is still running
WordPress, PHP, database or SIEM modules, fingerprinting did not identify it.

Practical levers:

```bash
--skip-modules ports,dirs,siem      # the usual slow ones
--profile safe                       # smaller footprint
--threads 16                         # more concurrency (louder)
--timeout 5                          # give up on unresponsive hosts sooner
```

Port scanning through `nmap` is normally the single largest contributor.

---

## PDF or Word export fails

```
RuntimeError: PDF export needs reportlab
RuntimeError: Word export needs python-docx
```

The `reports` extra is not installed:

```bash
pip install -e '.[reports]'      # or '.[all]'
```

---

## Port scanning reports an error

Usually `nmap` is missing (`sudo apt install nmap`), or the scan exceeded its
time budget on a filtered host. Some scan types additionally require elevated
privileges; without them nmap falls back to a slower connect scan.

---

## A scan is refused before it starts

By design. Check each in turn:

- `--authorized` is present
- `--confirm-target` exactly matches `-t`
- the target is not a private or reserved address (`--allow-private` for lab use)
- the target is inside your `--allowlist`, if you supplied one

The refusal message names the specific gate that failed.

---

## Still stuck

Open an issue with the output of `webosint doctor` and `webosint version`,
redacting target names, hostnames and addresses first.
