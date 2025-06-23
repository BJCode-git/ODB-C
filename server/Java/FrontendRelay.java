package server.Java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class FrontendRelay {
    private static final int PORT = 8080;

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Usage: java FrontendRelay <backendHost> <backendPort>");
            System.exit(1);
        }

        String backendHost = args[0];
        int backendPort = Integer.parseInt(args[1]);

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("[Frontend] Listening on port " + PORT);

        while (true) {
            try (
                Socket clientSocket = serverSocket.accept();
                Socket backendSocket = new Socket(backendHost, backendPort);
                InputStream clientIn = clientSocket.getInputStream();
                OutputStream clientOut = clientSocket.getOutputStream();
                InputStream backendIn = backendSocket.getInputStream();
                OutputStream backendOut = backendSocket.getOutputStream()
            ) {
                System.out.println("[Frontend] Accepted connection and connected to backend");

                // Forward request from client to backend
                byte[] buffer = new byte[Constants.BUFFER_SIZE];
                int bytesRead = clientIn.read(buffer);
                if (bytesRead != -1) {
                    backendOut.write(buffer, 0, bytesRead);
                    backendOut.flush();
                    System.out.println("[Frontend] Forwarded " + bytesRead + " bytes to backend");
                }

                // Read response from backend and send to client

                while( (bytesRead = backendIn.read(buffer)) != -1) {
                    clientOut.write(buffer, 0, bytesRead);
                    clientOut.flush();
                    System.out.println("[Frontend] Sent " + bytesRead + " bytes to client");
                    // Save the sent data to Constants.FE_SAVE_PATH
                    Files.write(Paths.get(Constants.FE_SAVE_PATH), buffer, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    System.out.println("[Frontend] Saved sent data to " + Constants.FE_SAVE_PATH);
                   
                }

            } catch (IOException e) {
                System.err.println("[Frontend] Connection error: " + e.getMessage());
            }
        }
    }
}
