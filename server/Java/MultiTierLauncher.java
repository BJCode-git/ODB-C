package server.Java;
import java.io.IOException;
import java.util.Map;

public class MultiTierLauncher {
    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length != 2) {
            System.err.println("Usage: java MultiTierLauncher <fileType> <relayCount>");
            System.exit(1);
        }

        String fileType = args[0];
        int relayCount = Integer.parseInt(args[1]);

        int backendPort = 9000;
        int frontendPort = 8080;
        int nextPort = backendPort;


        ProcessBuilder backendBuilder = new ProcessBuilder("java", "server.Java.BackendServer", fileType);
        if (Constants.USE_ODB) {
            Map<String, String> backendEnv = backendBuilder.environment();
            backendEnv.put("LD_PRELOAD", Constants.ODB_BE_PATH);
        }
        backendBuilder.inheritIO();
        Process backend = backendBuilder.start();

        Process[] relays = new Process[relayCount];
        for (int i = relayCount - 1; i >= 0; i--) {
            int listenPort = backendPort + i + 1;
            ProcessBuilder relayBuilder = new ProcessBuilder("java", "server.Java.IntermediaryRelay",
                    String.valueOf(listenPort), "localhost", String.valueOf(nextPort));
            if (Constants.USE_ODB) {
                Map<String, String> relayEnv = relayBuilder.environment();
                relayEnv.put("LD_PRELOAD", Constants.ODB_IS_PATH);
            }
            relayBuilder.inheritIO();
            relays[i] = relayBuilder.start();
            nextPort = listenPort;
        }

        ProcessBuilder frontendBuilder = new ProcessBuilder("java", "server.Java.FrontendRelay",
                "localhost", String.valueOf(nextPort));
        if (Constants.USE_ODB) {
            Map<String, String> frontendEnv = frontendBuilder.environment();
            frontendEnv.put("LD_PRELOAD", Constants.ODB_FE_PATH);
        }
        frontendBuilder.inheritIO();
        Process frontend = frontendBuilder.start();

        System.out.printf("\nAll tiers launched. Try:\n  wget http://localhost:%d/ -O result\n\n", frontendPort);

        backend.waitFor();
        for (Process r : relays) r.waitFor();
        frontend.waitFor();
    }
}