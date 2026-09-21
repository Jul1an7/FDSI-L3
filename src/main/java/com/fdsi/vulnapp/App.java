package com.fdsi.vulnapp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Versión REMEDIADA de la app del Laboratorio 04 (FDSI) — fase SAST.
 * Fallos OWASP corregidos (FIX-01..06) + calidad de código (SonarQube).
 */
public class App {

    private static final Logger log = LogManager.getLogger(App.class);
    private static final Pattern HOST_OK = Pattern.compile("^[a-zA-Z0-9.\\-]{1,253}$");
    private static Connection conn;

    public static void main(String[] args) throws IOException, SQLException {
        initDb();
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/login", App::handleLogin);
        server.createContext("/ping", App::handlePing);
        server.createContext("/file", App::handleFile);
        server.setExecutor(null);
        server.start();
        log.info("Servidor arrancado en http://localhost:8080");
    }

    private static void initDb() throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        }

        boolean exists;
        try (PreparedStatement check = conn.prepareStatement("SELECT 1 FROM users WHERE username = ?")) {
            check.setString(1, "admin");
            try (ResultSet rs = check.executeQuery()) {
                exists = rs.next();
            }
        }

        if (!exists) {
            String adminPass = System.getenv().getOrDefault("ADMIN_PASSWORD", "");
            if (adminPass.isEmpty()) {
                adminPass = UUID.randomUUID().toString();
                log.warn("ADMIN_PASSWORD no definida; se generó una contraseña temporal aleatoria.");
            }
            String hash = BCrypt.hashpw(adminPass, BCrypt.gensalt());
            try (PreparedStatement ins = conn.prepareStatement("INSERT INTO users (username, password) VALUES (?, ?)")) {
                ins.setString(1, "admin");
                ins.setString(2, hash);
                ins.executeUpdate();
            }
        }
    }


    private static void handleLogin(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String user = q.getOrDefault("user", "");
        String pass = q.getOrDefault("pass", "");
        try {
            boolean ok = false;
            try (PreparedStatement ps = conn.prepareStatement("SELECT password FROM users WHERE username = ?")) {
                ps.setString(1, user);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        ok = BCrypt.checkpw(pass, rs.getString("password"));
                    }
                }
            }
            respond(ex, 200, ok ? "Login OK" : "Login FAILED");
        } catch (SQLException e) {
            respond(ex, 500, "error");
        }
    }

    private static void handlePing(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String host = q.getOrDefault("host", "127.0.0.1");
        if (!HOST_OK.matcher(host).matches()) {
            respond(ex, 400, "host invalido");
            return;
        }
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        byte[] out = p.getInputStream().readAllBytes();
        respond(ex, 200, new String(out, StandardCharsets.UTF_8));
    }

    private static void handleFile(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String name = q.getOrDefault("name", "index.txt");
        Path base = Paths.get("files").toAbsolutePath().normalize();
        Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) {
            respond(ex, 400, "ruta invalida");
            return;
        }
        if (!Files.exists(target)) {
            respond(ex, 404, "not found");
            return;
        }
        byte[] data = Files.readAllBytes(target);
        respond(ex, 200, new String(data, StandardCharsets.UTF_8));
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