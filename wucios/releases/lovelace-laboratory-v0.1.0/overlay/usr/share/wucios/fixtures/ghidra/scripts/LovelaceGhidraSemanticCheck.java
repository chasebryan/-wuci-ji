// WuciOS Lovelace Laboratory: pinned benign headless-analysis acceptance.
// @category WuciOS

import java.nio.charset.StandardCharsets;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.util.GhidraProgramUtilities;

public class LovelaceGhidraSemanticCheck extends HeadlessScript {
    private static final String EXPECTED_NAME = "ghidra-smoke";
    private static final String EXPECTED_FORMAT =
        "Executable and Linking Format (ELF)";
    private static final String EXPECTED_LANGUAGE = "x86:LE:64:default";
    private static final String EXPECTED_MD5 =
        "7af3bf4a75edc982a574d9e0290f96fd";
    private static final String EXPECTED_SHA256 =
        "446c9e5b46a3eb21a7e09f2794bdd58c66491ebd927bc67c36b212d7da08eb8e";
    private static final String SEMANTIC_MARKER =
        "LOVELACE_GHIDRA_SEMANTIC_PASS";

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private void emitSemanticResult(String result) {
        System.out.print("\n" + result + "\n");
        System.out.flush();
    }

    @Override
    protected void run() throws Exception {
        require(currentProgram != null, "no imported program");
        require(isHeadlessAnalysisEnabled(), "headless analysis was disabled");
        require(!analysisTimeoutOccurred(), "analysis timed out");
        require(GhidraProgramUtilities.isAnalyzed(currentProgram),
            "program is not marked analyzed");
        require(EXPECTED_NAME.equals(currentProgram.getName()),
            "unexpected program name");
        require(EXPECTED_FORMAT.equals(currentProgram.getExecutableFormat()),
            "unexpected executable format");
        require(EXPECTED_LANGUAGE.equals(
            currentProgram.getLanguageID().toString()),
            "unexpected program language");
        require(EXPECTED_MD5.equals(currentProgram.getExecutableMD5()),
            "unexpected imported file identity");
        require(EXPECTED_SHA256.equals(currentProgram.getExecutableSHA256()),
            "unexpected imported file SHA-256 identity");
        require(currentProgram.getFunctionManager().getFunctionCount() > 0,
            "analysis produced no functions");
        require(currentProgram.getListing().getNumInstructions() >= 8,
            "analysis produced too few instructions");

        byte[] message =
            "lovelace-ghidra-smoke\n".getBytes(StandardCharsets.US_ASCII);
        Address found = currentProgram.getMemory().findBytes(
            currentProgram.getMinAddress(), message, null, true, monitor);
        require(found != null, "fixture message bytes were not imported");

        String[] arguments = getScriptArgs();
        if (arguments.length == 0) {
            emitSemanticResult(SEMANTIC_MARKER);
            return;
        }
        require(arguments.length == 2,
            "semantic challenge requires exactly two halves");
        String challenge = arguments[0] + arguments[1];
        require(challenge.matches("[0-9a-f]{64}"),
            "semantic challenge is invalid");
        emitSemanticResult(SEMANTIC_MARKER + " " + challenge);
    }
}
