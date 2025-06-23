package server.Java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class IntermediaryRelay {
    private static final int LISTEN_PORT = 9001;
    private static final int FORWARD_PORT = 9000; // Port of the backend
    private static final String FORWARD_HOST = "localhost";

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(LISTEN_PORT);
        System.out.println("[Intermediary] Listening on port " + LISTEN_PORT);

        while (true) {
            try (Socket clientSocket = serverSocket.accept();
                 Socket backendSocket = new Socket(FORWARD_HOST, FORWARD_PORT);
                 InputStream clientIn = clientSocket.getInputStream();
                 OutputStream clientOut = clientSocket.getOutputStream();
                 InputStream backendIn = backendSocket.getInputStream();
                 OutputStream backendOut = backendSocket.getOutputStream()) {

                System.out.println("[Intermediary] Accepted connection from frontend");

                byte[] buffer = new byte[Constants.BUFFER_SIZE];
                int bytesRead;

                while ((bytesRead = clientIn.read(buffer)) != -1) {
                    backendOut.write(buffer, 0, bytesRead);
                    backendOut.flush();
                    System.out.println("[Intermediary] Forwarded " + bytesRead + " bytes to backend");

                    while ((bytesRead = backendIn.read(buffer)) != -1) {
                        System.out.println("[Intermediary] Received " + bytesRead + " bytes from backend");
                        clientOut.write(buffer, 0, bytesRead);
                        clientOut.flush();
                        System.out.println("[Intermediary] Relayed " + bytesRead + " bytes to client");
                    }
                    // print error message
                    if (bytesRead == -1) {
                        System.err.println("[Intermediary] Error reading from backend");
                        break;
                    }
                }

            } catch (IOException e) {
                System.err.println("[Intermediary] Connection error: " + e.getMessage());
            }
        }
    }
}
