# .NET / managed assemblies

`identify_target.py` reports `pe-dotnet` when the PE has a CLR header.

## With ilspycmd
`run_provider.py dotnet:decompile app.dll --out NEW_DIR --record` produces a C# project.
Read it like source, but cite the evidence ID. Names and structure are a reconstruction,
and async/iterator state machines and lambdas are lowered.

## Without ilspycmd
- `strings:extract app.dll --record` covers the user-string heap (UTF-16), so URLs,
  messages and SQL appear here. Type/method names are in the `#Strings` heap (ASCII).
- `symbols:list` / `headers:info` show little for IL-only assemblies. Note that, and record
  an Unknown with `dotnet tool install -g ilspycmd` as the remedy.

## NativeAOT
A NativeAOT build is a native PE/ELF/Mach-O with no CLR header. Treat it as native code
(`native.md`). Method names often survive in the symbol table or in reflection metadata
strings. Ghidra gives the best results here.

## Comparing builds
`diff_versions.py` works at member level for packaged builds (zip/msix). For two
decompiled outputs, diff the generated C# directories (`diff -ru`) and record the
diff as evidence (`evidence.py record --provider diff --operation compare:sources ...`).
