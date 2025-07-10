package server.Java;
public class Constants {
    public static final int     BUFFER_SIZE  = 16384;
    public static final Boolean USE_ODB      = true;
    public static final String  HTML_FILE    = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/rsc/lorem.html";
    public static final String  IMAGE_FILE   = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/rsc/img.jpg";
    public static final String  VIDEO_FILE   = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/rsc/vid.mp4";
    public static final String  ODB_BE_PATH  = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/lib/libBE_odb.so";
    public static final String  ODB_IS_PATH  = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/lib/libIS_odb.so";
    public static final String  ODB_FE_PATH  = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/lib/libFE_odb.so";
    public static final String  BE_SAVE_PATH  = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/results/BE.save";
    public static final String  FE_SAVE_PATH  = "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/results/FE.save";

    public static String getFileName(String type) {
        switch (type.toLowerCase()) {
            case "html":
                return HTML_FILE;
            case "image":
                return IMAGE_FILE;
            case "video":
                return VIDEO_FILE;
            default:
                return null;
        }
    }

    public static String getContentType(String type) {
        switch (type.toLowerCase()) {
            case "html":
                return "text/html";
            case "image":
                return "image/jpeg";
            case "video":
                return "video/mp4";
            default:
                return "application/octet-stream";
        }
    }
}
