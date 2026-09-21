package com.fdsi.vulnapp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

/**
 * App deliberadamente vulnerable para el Laboratorio 04 (FDSI) — fase SAST.
 * NO usar en producción. Cada fallo está marcado con [VULN-0X].
 */
public class App {

    private static final Logger log = LogManager.getLogger(App.class);

    // [VULN-03] Secreto hardcodeado (CWE-798 / OWASP A07:2021).
    // Una credencial/clave jamas debe vivir en el codigo fuente ni en el repo.
    private static final String API_KEY = "sk_live_51H8xQe2eZvKYlo8CkL9m3nOpQrStUvWxYz";

    private static Connection conn;

    public static void main(String[] args) throws Exception {
        initDb();
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/login", App::handleLogin);
        server.createContext("/ping", App::handlePing);
        server.createContext("/file", App::handleFile);
        server.setExecutor(null);
        server.start();
        // Se registra la API_KEY en el log: mala practica adicional (secreto en logs).
        log.info("Servidor arrancado en http://localhost:8080 con API_KEY=" + API_KEY);
    }

    private static void initDb() throws Exception {
        conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement st = conn.createStatement();
        st.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        // password = MD5('admin123') = 0192023a7bbd73250516f069df18b500
        st.execute("INSERT INTO users (username, password) "
                + "SELECT 'admin', '0192023a7bbd73250516f069df18b500' "
                + "WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin')");
        st.close();
    }

    // ---- /login : SQL Injection + hashing debil ----
    private static void handleLogin(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String user = q.getOrDefault("user", "");
        String pass = q.getOrDefault("pass", "");
        try {
            // [VULN-04] Hashing debil con MD5 (CWE-327 / OWASP A02:2021).
            // MD5 es rapido y esta roto para passwords; deberia ser bcrypt/argon2.
            String hashed = md5(pass);

            // [VULN-01] SQL Injection por concatenacion (CWE-89 / OWASP A03:2021).
            // La entrada del usuario entra sin sanear a la consulta.
            String sql = "SELECT * FROM users WHERE username = '" + user
                    + "' AND password = '" + hashed + "'";
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery(sql);
            String resp = rs.next() ? "Login OK" : "Login FAILED";
            rs.close();
            st.close();
            respond(ex, 200, resp);
        } catch (Exception e) {
            respond(ex, 500, "error: " + e.getMessage());
        }
    }

    // ---- /ping : Command Injection ----
    private static void handlePing(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String host = q.getOrDefault("host", "127.0.0.1");
        try {
            // [VULN-02] Command Injection (CWE-78 / OWASP A03:2021).
            // Se concatena la entrada del usuario dentro de un comando del sistema.
            Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
            byte[] out = p.getInputStream().readAllBytes();
            respond(ex, 200, new String(out, StandardCharsets.UTF_8));
        } catch (Exception e) {
            respond(ex, 500, "error: " + e.getMessage());
        }
    }

    // ---- /file : Path Traversal ----
    private static void handleFile(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String name = q.getOrDefault("name", "index.txt");
        try {
            // [VULN-06] Path Traversal (CWE-22 / OWASP A01:2021).
            // Sin validar 'name', ?name=../../etc/passwd escapa del directorio.
            byte[] data = Files.readAllBytes(Paths.get("files/" + name));
            respond(ex, 200, new String(data, StandardCharsets.UTF_8));
        } catch (Exception e) {
            respond(ex, 404, "not found: " + e.getMessage());
        }
    }

    private static String md5(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                      URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
        }
        return m;
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
