# JavaScript, Electron and ASAR

`uv run $S/js_bundle.py <app.asar | App.app | dir | file.js> --workdir W --record [--trace TERM]... [--extract NEW_DIR]`

It reads ASAR archives directly and never executes code. It reports, with `file:line`:

| Field | Meaning |
|---|---|
| `package` | name, version, main, dependencies from package.json |
| `ipc.main_handlers` | `ipcMain.handle/on` channels: what the privileged main process accepts |
| `ipc.renderer_calls` | `ipcRenderer.invoke/send`: what the UI asks for |
| `ipc_unhandled_renderer_calls` | channels the renderer uses that no main handler covers (dead feature, dynamic registration, or a handler in an unpacked file) |
| `ipc.exposed_apis` | `contextBridge.exposeInMainWorld` names (the renderer-visible surface) |
| `endpoints` / `network_calls` | URL literals and fetch/axios/WebSocket/XHR call sites |
| `security_flags` | nodeIntegration:true, contextIsolation:false, sandbox:false, webSecurity:false, openExternal, child_process, eval, protocol handlers |
| `module_edges` / `external_modules` | require/import graph |
| `sourcemaps` | `sourceMappingURL`: original sources may be recoverable |
| `secret_like` | key/secret/token assignments (values redacted) |
| `traces` | every line mentioning each `--trace` term |

## Workflow

1. Run once on the whole app. For an Electron `.app`, pass the bundle and the script finds
   `Contents/Resources/app.asar`.
2. Answer "what does it talk to / expose" from the summary.
3. To trace a feature, run `--trace <channel or keyword>`, then read the specific files
   (`--extract NEW_DIR`, then Read). Follow renderer call → preload bridge → main handler →
   module that does the work.
4. Security review: combine `security_flags` with `exposed_apis`. `nodeIntegration:true` +
   `contextIsolation:false` means renderer content runs with Node privileges. `shell.openExternal` fed
   from IPC without validation is a classic issue. Report these as code-level findings
   with locations, not as confirmed exploits.

## Limits to state

- Channel names or URLs built at runtime (concatenation, template variables, config
  files) aren't resolved. A variable passed to `axios.post(LICENSE_API, …)` appears under
  `endpoints` (the URL literal), not `network_calls`. Connect them by reading the file.
- Minified bundles hide structure. Use the source map if present, and use `--trace` on stable
  strings (error messages, channel names, URLs).
- `app.asar.unpacked` entries are listed but not read from the archive. Analyze that
  directory separately (native `.node` modules route to `native.md`).
- Bun `--compile` executables embed the JS module graph. Use `strings:extract --grep` to
  locate modules, or carve them out, then run js_bundle on the extracted sources.
- Runtime confirmation (which handler actually fires) needs the app running. See
  `runtime-observation.md`.
