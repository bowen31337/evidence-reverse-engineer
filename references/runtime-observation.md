# Runtime observation

Running a target executes its code. Decide which of three cases you are in.

## 1. Already authorized: a sandboxed confirmation run
Go ahead **without asking** when all of these hold:
- the user supplied the target themselves, and their request implies running it: a CTF or
  crackme ("give me a key that works"), their own build, "does this input work?";
- `run:process` gives you a sandbox (macOS sandbox-exec or Linux unshare): no network,
  writes only to a temp dir, minimal environment, short timeout;
- the run is a narrow confirmation of a specific static finding (one key, one flag), not
  open-ended exploration.

```bash
uv run $S/run_provider.py run:process ./crackme --arg 'REA?-AAAAAAD' --workdir W --record
```
This records exit code, stdout and stderr as `controlled-replay` evidence. That's the only
kind of evidence that can support a claim marked `"runtime": true`. Also try one input
that should fail, so the run discriminates.

## 2. Ask first
Explain what will run, with which arguments, and what could change. Then wait for approval when:
- the user says not to execute it, or it's a third-party or vendor binary they're evaluating,
  suspected malware, or something they didn't supply;
- no sandbox works on this host (`doctor.py` shows `sandboxed_run.available: false`, and
  `run:process` refuses with `missing_provider: sandbox`). Suggest a disposable VM or
  container first. Pass `--no-sandbox` only after the user explicitly agrees to an unisolated run;
- the run needs network (`--allow-network`), real credentials, a debugger, root/SIP
  changes (dtruss), or touches the user's real HOME, keychain or files;
- the program is long-running, interactive, or installs/updates anything.

## 3. Don't run
Encrypted/DRM-protected targets, anything whose purpose is circumventing protection, or
when static evidence already answers the question and running adds nothing.

A sandboxed run can still behave differently from a normal one (a denied network call
may change the code path). Keep the sandbox limitation in the evidence, and don't
generalise one run to every input.

## Recipes (macOS / Linux)

**Confirm a derived key / input** (case 1)
```bash
uv run $S/run_provider.py run:process ./crackme --arg 'REA?-AAAAAAD' --workdir W --record   # expect ok
uv run $S/run_provider.py run:process ./crackme --arg 'REA?-AAAAAAA' --workdir W --record   # expect rejection
```

**Break on a function, read arguments** (lldb)
```bash
lldb --batch -o "b strncmp" -o "run" -o "register read x0 x1 x2" -o "x/s \$x0" -o "x/s \$x1" -o "kill" -- ./target ARGS
```

**System calls / file and network activity**
- Linux: `strace -f -e trace=file,network -o W/raw/strace.txt ./target ARGS`
- macOS: `sudo dtruss -f ./target` (needs root and SIP allowances; ask first, or skip)

**Frida** (if installed): `frida-trace -f ./target -i 'connect' -i 'SSL_write'`

**Electron**: launch with `--inspect=0` / `--remote-debugging-port=9222` against a
throwaway profile, then observe IPC and network via DevTools/CDP.

## Static ↔ runtime correlation
State the hypothesis from static evidence ("v2 calls upload_metrics from sync_data"),
run the narrowest observation that can confirm or contradict it, record it, and link
both: `evidence.py record --infer "runtime confirms ..." --link <static-id> --link <runtime-id>`.
If runtime contradicts static, keep both and add an Unknown that explains the gap
(e.g. a feature flag or an environment check).
