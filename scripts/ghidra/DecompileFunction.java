// Ghidra headless post-script used by run_provider.py ghidra:decompile.
// Args: <function name or 0xADDRESS> <output .c path>
// Writes pseudo-C for the requested function (or every function if name is "*").
// Tested with Ghidra 12.2 headless (Homebrew) on an arm64 Mach-O; uses only the stable
// DecompInterface API (Ghidra 10+).
//@category evidence-reverse-engineer

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class DecompileFunction extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String want = args.length > 0 ? args[0] : "main";
        String outPath = args.length > 1 ? args[1] : "decompiled.c";

        List<Function> targets = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        Address addr = want.startsWith("0x") ? toAddr(want) : null;
        while (it.hasNext()) {
            Function f = it.next();
            String n = f.getName();
            if (want.equals("*") || n.equals(want) || n.equals("_" + want) || ("_" + n).equals(want)
                    || (addr != null && f.getBody().contains(addr))) {
                targets.add(f);
            }
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new FileWriter(outPath))) {
            if (targets.isEmpty()) {
                out.println("// function not found: " + want);
            }
            for (Function f : targets) {
                DecompileResults r = ifc.decompileFunction(f, 120, monitor);
                out.println("// " + f.getName() + " @ " + f.getEntryPoint());
                if (r != null && r.decompileCompleted()) {
                    out.println(r.getDecompiledFunction().getC());
                } else {
                    out.println("// decompilation failed: " + (r == null ? "null" : r.getErrorMessage()));
                }
            }
        } finally {
            ifc.dispose();
        }
    }
}
