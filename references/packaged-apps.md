# Packaged applications and archives

## Inventory first
`run_provider.py artifact:inventory pkg --record` (`--detail complete` for every member)
gives every member's sha256 and **content-identified** kind, the executables, and
nested containers. Kinds ending in `?` were guessed from the extension only. A
`lib/foo.so` that's really text shows as `elf?`, not `elf`.

Then extract only what the question needs:
`artifact:extract pkg --out NEW_DIR --member bin/tool --member config.json`
Extraction refuses path-traversal names and non-empty output directories.

Nested containers (`extras/plugins.zip`) need their own inventory pass. Say how deep
you went: "inventoried 2 levels; 1 nested zip not opened" is a valid limitation.

## Specific packagings
| Packaging | How to reach the application layer |
|---|---|
| IPA | `Payload/<App>.app/<App>` is the Mach-O. Check `headers:info` → `encrypted` (App Store builds are FairPlay-encrypted) |
| macOS `.app` | `Contents/MacOS/<exe>` (native). `Contents/Resources/app.asar` means Electron (js_bundle) |
| DMG | `hdiutil attach -readonly -nobrowse -mountpoint W/mnt image.dmg`, analyze, then `hdiutil detach W/mnt`. Read-only, and nothing is installed |
| PyInstaller exe | The appended CArchive (marker `MEI\x0c\x0b\x0a\x0b\x0e`) holds the `.pyc` app. The bootloader is generic. Carve it with an extractor if available, else `strings:extract --grep '\.py'` to list modules |
| Bun `--compile` | Embedded JS module graph. Find module sources with `strings:extract --grep 'import|require'`, then js_bundle on the carved text |
| MSIX/AppX | ZIP with `AppxManifest.xml`. Route the contained PE/.NET files |
| JAR/WAR | jadx, or inventory + `strings:extract` on classes |
| Python wheel | ZIP of source. Read it directly: this is source, not a shipped binary |

## Version-to-version
`diff_versions.py old.zip new.zip` compares members by sha256. Route each changed
executable member to `diff_versions.py` again for a function-level diff.
