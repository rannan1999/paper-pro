package io.papermc.paper.sbx;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

public class App {
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, String> DOT_ENV = loadDotEnv();

    // ==================== 【自订变量映射】 ====================
    private static final String UUID = env("UUID", "faacf142-dee8-48c2-8558-641123eb939c");
    private static final int PORT = envInt("PORT", 3000);
    private static final String NEZHA_SERVER = env("NEZHA_SERVER", "nezha.mingfei1981.eu.org");
    private static final String NEZHA_PORT = env("NEZHA_PORT", "443");
    private static final String NEZHA_KEY = env("NEZHA_KEY", "VcNmAA8ErRWXY9lEpl");
    private static final String ARGO_DOMAIN = env("ARGO_DOMAIN", "latvi.mingfei1982.eu.org");
    private static final String ARGO_TOKEN = env("ARGO_TOKEN", "eyJhIjoiMGYxNTA1MzUwOTRjNDhlZjNmM2ZjZTA2M2E4N2M1N2YiLCJ0IjoiMmQ1NmIzMDctOGE2My00MWI2LWEwM2UtYzJjMDIyNDg0MDI2IiwicyI6IlpXVmlOamt6WW1FdFpUUXpOeTAwT1dKaUxXRTNZakV0WldKaU1tRXlOekU0TWpndyJ9");
    private static final String WSPORT = env("WSPORT", "8001");
    private static final String TOKEN = env("TOKEN", "babama123");
    private static final String OPERA = env("OPERA", "0");
    private static final String IPS = env("IPS", "4");
    private static final String COUNTRY = env("COUNTRY", "AM");

    // ==================== 【系统路径与运行环境】 ====================
    private static final Path TMP_DIR = Path.of("/tmp");
    private static final String ARCH = detectArch();
    private static final List<Process> MANAGED_PROCESSES = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        // 参数严格检查 (COUNTRY, OPERA, IPS)
        validateParameters();

        // 尝试覆盖设置 DNS (对应 echo nameserver > /etc/resolv.conf)
        setDnsResolv();

        // 1) 启动极简 HTTP 监听服务器防止面板断定容器崩溃 (对应 start.sh 内置 nc 循环)
        startKeepAliveServer(PORT);

        // 检测并匹配架构下载链接
        String echUrl, operaUrl, cloudflaredUrl, nezhaUrl;
        if ("arm64".equals(ARCH)) {
            echUrl = "https://github.com/webappstars/ech-hug/releases/download/3.0/ech-tunnel-linux-arm64";
            operaUrl = "https://github.com/Alexey71/opera-proxy/releases/download/v1.22.0/opera-proxy.freebsd-arm64";
            cloudflaredUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64";
            nezhaUrl = "https://github.com/babama1001980/good/releases/download/npc/arm64agent";
        } else {
            echUrl = "https://github.com/webappstars/ech-hug/releases/download/3.0/ech-tunnel-linux-amd64";
            operaUrl = "https://github.com/Alexey71/opera-proxy/releases/download/v1.22.0/opera-proxy.linux-amd64";
            cloudflaredUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64";
            nezhaUrl = "https://github.com/babama1001980/good/releases/download/npc/amd64agent";
        }

        // 下载二进制程序到 /tmp 目录
        Path echBin = downloadFile(echUrl, "ech-server-linux");
        Path operaBin = downloadFile(operaUrl, "opera-linux");
        Path cloudflaredBin = downloadFile(cloudflaredUrl, "cloudflared-linux");
        Path nezhaBin = null;

        if (!NEZHA_SERVER.isEmpty() && !NEZHA_KEY.isEmpty()) {
            nezhaBin = downloadFile(nezhaUrl, "iccagent");
        }

        // 确定 ECH 端口
        int echPort = WSPORT.isEmpty() ? getFreePort() : Integer.parseInt(WSPORT);
        int operaPort = getFreePort();

        // 注册退出钩子，保证进程不残留
        Runtime.getRuntime().addShutdownHook(new Thread(App::stopAllProcesses, "shutdown-hook"));

        // 1) 启动哪吒探针
        if (nezhaBin != null && Files.exists(nezhaBin)) {
            List<String> tlsPorts = List.of("443", "8443", "2096", "2087", "2083", "2053");
            List<String> nezhaCmd = new ArrayList<>();
            nezhaCmd.add(nezhaBin.toString());

            if (!NEZHA_PORT.isEmpty()) {
                // 命令行直连模式
                nezhaCmd.add("-s");
                nezhaCmd.add(NEZHA_SERVER + ":" + NEZHA_PORT);
                nezhaCmd.add("-p");
                nezhaCmd.add(NEZHA_KEY);
                if (tlsPorts.contains(NEZHA_PORT)) {
                    nezhaCmd.add("--tls");
                }
            } else {
                // 写入配置文件模式
                String serverHostPort = NEZHA_SERVER.contains(":") ? NEZHA_SERVER.substring(NEZHA_SERVER.lastIndexOf(':') + 1) : "";
                boolean isTls = tlsPorts.contains(serverHostPort);
                Path yamlPath = TMP_DIR.resolve("nezha.yaml");
                String yamlConfig = "client_secret: " + NEZHA_KEY + "\n" +
                        "debug: false\n" +
                        "disable_auto_update: true\n" +
                        "disable_command_execute: false\n" +
                        "disable_force_update: true\n" +
                        "disable_nat: false\n" +
                        "disable_send_query: false\n" +
                        "gpu: false\n" +
                        "insecure_tls: false\n" +
                        "ip_report_period: 1800\n" +
                        "report_delay: 1\n" +
                        "server: " + NEZHA_SERVER + "\n" +
                        "skip_connection_count: false\n" +
                        "skip_procs_count: false\n" +
                        "temperature: false\n" +
                        "tls: " + isTls + "\n" +
                        "use_gitee_to_upgrade: false\n" +
                        "use_ipv6_country_code: false\n" +
                        "uuid: " + UUID;
                Files.writeString(yamlPath, yamlConfig, StandardCharsets.UTF_8);
                nezhaCmd.add("-c");
                nezhaCmd.add(yamlPath.toString());
            }
            startExternalProcess("nezha-agent", nezhaCmd);
        }

        // 2) 启动 Opera Proxy
        if ("1".equals(OPERA) && operaBin != null && Files.exists(operaBin)) {
            List<String> operaCmd = List.of(
                    operaBin.toString(),
                    "-country", COUNTRY.toUpperCase(),
                    "-socks-mode",
                    "-bind-address", "127.0.0.1:" + operaPort
            );
            startExternalProcess("opera-proxy", operaCmd);
        }

        // 3) 启动 ECH Tunnel
        if (echBin != null && Files.exists(echBin)) {
            sleep(1000); // 稍作延时，等待 Opera Proxy 启动就绪
            List<String> echCmd = new ArrayList<>();
            echCmd.add(echBin.toString());
            echCmd.add("-l");
            echCmd.add("ws://0.0.0.0:" + echPort);
            if (!TOKEN.isEmpty()) {
                echCmd.add("-token");
                echCmd.add(TOKEN);
            }
            if ("1".equals(OPERA)) {
                echCmd.add("-f");
                echCmd.add("socks5://127.0.0.1:" + operaPort);
            }
            startExternalProcess("ech-server", echCmd);
        }

        // 后台开启 3 分钟定时自动销毁文件任务
        startDelayedCleanupTask();

        // 4) 启动 Cloudflared 进程（并阻塞前台或保活运行）
        if (cloudflaredBin != null && Files.exists(cloudflaredBin)) {
            // 静默更新 cloudflared
            try {
                new ProcessBuilder(cloudflaredBin.toString(), "update").start().waitFor();
            } catch (Exception ignored) {}

            List<String> cfCmd = new ArrayList<>();
            cfCmd.add(cloudflaredBin.toString());
            cfCmd.add("--edge-ip-version");
            cfCmd.add(IPS);
            cfCmd.add("--protocol");
            cfCmd.add("http2");

            if (!ARGO_TOKEN.isEmpty()) {
                // 固定隧道模式 - 直接在 Java 主线程中 exec 运行（阻塞主进程，维持前台）
                cfCmd.add("tunnel");
                cfCmd.add("run");
                cfCmd.add("--token");
                cfCmd.add(ARGO_TOKEN);
                
                System.out.println("Starting Cloudflared in Token run-mode...");
                ProcessBuilder pb = new ProcessBuilder(cfCmd);
                pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                pb.redirectError(ProcessBuilder.Redirect.DISCARD);
                Process argoProcess = pb.start();
                synchronized (MANAGED_PROCESSES) {
                    MANAGED_PROCESSES.add(argoProcess);
                }
                argoProcess.waitFor();
            } else {
                // 临时隧道模式
                int metricsPort = getFreePort();
                cfCmd.add("tunnel");
                cfCmd.add("--url");
                cfCmd.add("127.0.0.1:" + echPort);
                cfCmd.add("--metrics");
                cfCmd.add("0.0.0.0:" + metricsPort);

                startExternalProcess("cloudflared", cfCmd);

                // 阻断主线程，等同于 tail -f /dev/null
                System.out.println("Cloudflared running in Quick Tunnel mode. Keeping app alive...");
                new CountDownLatch(1).await();
            }
        } else {
            // 如果没开 Cloudflared，也保持阻塞，不让 Java 主进程退出
            new CountDownLatch(1).await();
        }
    }

    /**
     * 参数合法性校验
     */
    private static void validateParameters() {
        String countryUpper = COUNTRY.toUpperCase();
        if ("1".equals(OPERA)) {
            if (!List.of("AM", "AS", "EU").contains(countryUpper)) {
                System.err.println("Error: Invalid COUNTRY code for OPERA mode!");
                System.exit(1);
            }
        } else if (!"0".equals(OPERA)) {
            System.err.println("Error: OPERA must be 0 or 1!");
            System.exit(1);
        }
        if (!"4".equals(IPS) && !"6".equals(IPS)) {
            System.err.println("Error: IPS must be 4 or 6!");
            System.exit(1);
        }
    }

    /**
     * 自动执行下载并设置权限
     */
    private static Path downloadFile(String url, String localName) {
        Path target = TMP_DIR.resolve(localName);
        if (Files.exists(target)) {
            target.toFile().setExecutable(true, false);
            return target;
        }
        Path tmp = TMP_DIR.resolve(localName + ".download");
        try {
            System.out.println("Downloading: " + url);
            HttpRequest request = HttpRequest.newBuilder(URI.create(url)).GET().build();
            HttpResponse<byte[]> response = HTTP.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() == 200) {
                Files.write(tmp, response.body());
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
                target.toFile().setExecutable(true, false);
                return target;
            }
        } catch (Exception e) {
            System.err.println("Failed to download " + localName + ": " + e.getMessage());
        } finally {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) {}
        }
        return null;
    }

    /**
     * 启动并托管外部子进程
     */
    private static void startExternalProcess(String name, List<String> command) {
        Thread thread = new Thread(() -> {
            try {
                ProcessBuilder pb = new ProcessBuilder(command);
                pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                pb.redirectError(ProcessBuilder.Redirect.DISCARD);
                Process process = pb.start();
                synchronized (MANAGED_PROCESSES) {
                    MANAGED_PROCESSES.add(process);
                }
                int code = process.waitFor();
                System.out.println(name + " exited with code: " + code);
            } catch (Exception e) {
                System.err.println("Failed to run external process: " + name + " -> " + e.getMessage());
            }
        }, name + "-daemon");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * 强制覆盖设定 DNS (容错处理)
     */
    private static void setDnsResolv() {
        try {
            Path resolvConf = Path.of("/etc/resolv.conf");
            Files.writeString(resolvConf, "nameserver 1.1.1.1\nnameserver 1.0.0.1\n", StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
    }

    /**
     * 3 分钟后定时无痕清理任务
     */
    private static void startDelayedCleanupTask() {
        Thread cleanupThread = new Thread(() -> {
            sleep(180_000); // 180 秒（3 分钟）
            System.out.println("Executing 3-minute secure auto-delete task...");
            for (String file : List.of("ech-server-linux", "opera-linux", "cloudflared-linux", "iccagent", "nezha.yaml")) {
                try {
                    Files.deleteIfExists(TMP_DIR.resolve(file));
                } catch (IOException ignored) {}
            }
            System.out.println("Sensitive binaries and configs deleted from memory/disk.");
        }, "delayed-cleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    /**
     * 保活 HTTP 监听，防止面板因无端口监听判定容器宕机
     */
    private static void startKeepAliveServer(int port) {
        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                while (!Thread.currentThread().isInterrupted()) {
                    try (Socket socket = serverSocket.accept();
                         OutputStream os = socket.getOutputStream()) {
                        String response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOK";
                        os.write(response.getBytes(StandardCharsets.UTF_8));
                        os.flush();
                    } catch (IOException ignored) {}
                }
            } catch (IOException e) {
                System.err.println("Port " + port + " keep-alive server binding failed: " + e.getMessage());
            }
        }, "keep-alive");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    /**
     * 关闭钩子：杀死所有托管的子进程
     */
    private static void stopAllProcesses() {
        System.out.println("Shutting down Java process, killing all subprocesses...");
        synchronized (MANAGED_PROCESSES) {
            for (Process p : MANAGED_PROCESSES) {
                if (p.isAlive()) {
                    p.destroyForcibly();
                }
            }
            MANAGED_PROCESSES.clear();
        }
    }

    // ==================== 【工具型函数】 ====================

    private static int getFreePort() {
        return RANDOM.nextInt(20000) + 10000;
    }

    private static String detectArch() {
        String arch = System.getProperty("os.arch", "").toLowerCase();
        return arch.contains("aarch64") || arch.contains("arm64") ? "arm64" : "amd64";
    }

    private static String env(String name, String fallback) {
        String value = DOT_ENV.get(name);
        if (value == null) value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static int envInt(String name, int fallback) {
        try { return Integer.parseInt(env(name, String.valueOf(fallback))); } catch (Exception e) { return fallback; }
    }

    private static Map<String, String> loadDotEnv() {
        Map<String, String> values = new LinkedHashMap<>();
        Path envPath = Path.of(".env").toAbsolutePath().normalize();
        if (!Files.exists(envPath)) return values;
        try {
            for (String line : Files.readAllLines(envPath, StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                if (trimmed.startsWith("export ")) trimmed = trimmed.substring(7).trim();
                int equals = trimmed.indexOf('=');
                if (equals > 0) {
                    values.put(trimmed.substring(0, equals).trim(), trimmed.substring(equals + 1).trim());
                }
            }
        } catch (IOException ignored) {}
        return values;
    }

    private static void sleep(long millis) {
        try { Thread.sleep(millis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
