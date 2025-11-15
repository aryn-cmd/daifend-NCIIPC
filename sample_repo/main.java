// main.java
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

class Main {
    public static void main(String[] args) {
        String userInput = "' OR '1'='1"; // sample malicious-looking input for tests

        System.out.println("=== Vulnerability demos (do not execute with real untrusted inputs) ===");
        System.out.println("Vulnerable SQL (string concatenation):");
        System.out.println(VulnerableExamples.buildVulnerableSql(userInput));
        System.out.println();

        System.out.println("Safe SQL pattern (use PreparedStatement, shown as template):");
        System.out.println(VulnerableExamples.buildSafeSqlPlaceholder(userInput));
        System.out.println();

        System.out.println("Vulnerable path (concatenation):");
        System.out.println(VulnerableExamples.buildFilePath(userInput));
        System.out.println();

        System.out.println("Normalized path (validated):");
        System.out.println(VulnerableExamples.normalizePath(userInput));
        System.out.println();

        System.out.println("Serialized harmless example (base64):");
        System.out.println(VulnerableExamples.serializeExample());
    }
}

class VulnerableExamples {
    public static String buildVulnerableSql(String input) {
        return "SELECT * FROM users WHERE name = '" + input + "';";
    }

    public static String buildSafeSqlPlaceholder(String input) {
        return "PreparedStatement template: SELECT * FROM users WHERE name = ? (use PreparedStatement and setString with user input)";
    }

    public static String buildFilePath(String input) {
        return "/tmp/" + input;
    }

    public static String normalizePath(String input) {
        Path p = Paths.get("/tmp", input).normalize();
        // ensure the normalized path stays under /tmp
        if (!p.startsWith(Paths.get("/tmp"))) {
            return Paths.get("/tmp").toString();
        }
        return p.toString();
    }

    public static String serializeExample() {
        try {
            // simple harmless serializable object example
            String example = "example";
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(example);
            oos.close();
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (IOException e) {
            return "";
        }
    }
}
