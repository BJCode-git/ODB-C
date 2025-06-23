package server.Java;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class BackendServer {
    private static final int PORT = 9000;

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("Usage: java BackendServer <fileType>");
            System.exit(1);
        }

        String fileType = args[0];
        String filePath;  
        //String contentType;
        String extension;

        switch (fileType.toLowerCase()) {
            case "txt":
                filePath = Constants.HTML_FILE;
                extension = "html";
                //contentType = "text/html";
                break;
            case "img":
                filePath = Constants.IMAGE_FILE;
                extension = "jpg";
                //contentType = "image/jpeg";
                break;
            case "vid":
                filePath = Constants.VIDEO_FILE;
                extension = "mp4";
                //contentType = "video/mp4";
                break;
            default:
                System.err.println("Unsupported file type: " + fileType);
                return;
        }

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("[Backend] Listening on port " + PORT);

        while (true) {
            try (Socket socket = serverSocket.accept();
                 OutputStream out = socket.getOutputStream();
                 InputStream in = socket.getInputStream()) {

                System.out.println("[Backend] Accepted connection");

                // Read basic HTTP request (not parsed in detail)
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    // Just consume headers
                }

                // Send HTTP response headers
                //String headers = "HTTP/1.1 200 OK\r\n" +
                //                 "Content-Type: " + contentType + "\r\n" +
                //                 "Connection: close\r\n" +
                //                 "\r\n";
                //out.write(headers.getBytes());

                // Read file data in chunks and send to client
                try (InputStream fileIn = Files.newInputStream(Paths.get(filePath))) {
                    byte[] buffer = new byte[Constants.BUFFER_SIZE];
                    int bytesRead;
                    int totalBytesSent = 0;

                    while ((bytesRead = fileIn.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                        out.flush();
                        totalBytesSent += bytesRead;
                        // Save the sent data to Constants.BE_SAVE_PATH
                        Files.write(Paths.get(Constants.BE_SAVE_PATH+"."+extension), buffer, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                        System.out.println("[Backend] Saved sent data to " + Constants.BE_SAVE_PATH);
                    }

                    System.out.println("[Backend] Sent file (" + totalBytesSent + " bytes)");
                    Thread.sleep(3000);
                    socket.close();
                    break;
                }

            } catch (IOException e) {
                System.err.println("[Backend] Connection error: " + e.getMessage());
            }
            catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        serverSocket.close();
    }
}
