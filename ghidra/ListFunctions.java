// rekit Ghidra headless post-script: list functions with size + signature.
// Usage: analyzeHeadless <proj> rekit -import <bin> -postScript ListFunctions.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class ListFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("// rekit function list for " + currentProgram.getName());
        int n = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            n++;
            println(String.format("%-45s %-14s size=%-6d params=%d",
                    f.getName(), f.getEntryPoint().toString(), f.getBody().getNumAddresses(),
                    f.getParameterCount()));
        }
        println("// total functions: " + n);
    }
}
