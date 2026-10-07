// rekit Ghidra headless post-script: decompile every function to a C file.
// Usage: analyzeHeadless <proj> rekit -import <bin> -postScript DecompileAll.java <out.c>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("DecompileAll: no output path given");
            return;
        }
        File outFile = new File(args[0]);
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.setSimplificationStyle("decompile");
        boolean opened = di.openProgram(currentProgram);
        if (!opened) {
            println("DecompileAll: could not open program in decompiler");
            return;
        }
        int total = 0;
        int ok = 0;
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outFile)))) {
            pw.println("// rekit headless decompile: " + currentProgram.getName());
            FunctionManager fm = currentProgram.getFunctionManager();
            for (Function f : fm.getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                total++;
                pw.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint() + " ==== */");
                DecompileResults res = di.decompileFunction(f, 60, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    pw.println(res.getDecompiledFunction().getC());
                    ok++;
                } else {
                    String err = (res == null) ? "null result" : res.getErrorMessage();
                    pw.println("// decompile failed: " + err);
                }
                pw.println();
            }
        }
        di.dispose();
        println("DecompileAll: functions=" + total + " decompiled=" + ok + " -> " + outFile.getAbsolutePath());
    }
}
