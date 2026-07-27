// WuciOS Lovelace Laboratory: generic NOXFRAME headless-analysis acceptance.
// @category WuciOS

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.util.GhidraProgramUtilities;

public class LovelaceGhidraBrokerSemanticCheck extends HeadlessScript {
    private static final String SEMANTIC_MARKER =
        "LOVELACE_NOXFRAME_GHIDRA_SEMANTIC_PASS";

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    @Override
    protected void run() throws Exception {
        require(getScriptArgs().length == 0,
            "broker semantic check accepts no arguments");
        require(currentProgram != null, "no imported program");
        require(isHeadlessAnalysisEnabled(), "headless analysis was disabled");
        require(!analysisTimeoutOccurred(), "analysis timed out");
        require(GhidraProgramUtilities.isAnalyzed(currentProgram),
            "program is not marked analyzed");

        System.out.print("\n" + SEMANTIC_MARKER + "\n");
        System.out.flush();
    }
}
