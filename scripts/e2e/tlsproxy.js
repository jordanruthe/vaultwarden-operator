// Minimal TLS-terminating reverse proxy.
//
// The Bitwarden web vault client refuses to talk to a plain-HTTP server (even
// on loopback), so this fronts the throwaway in-cluster Vaultwarden with a
// self-signed HTTPS listener purely so the browser-driven registration flow
// in register.js is allowed to run.
//
// Usage: node tlsproxy.js <certPath> <keyPath> <listenPort> <targetUrl>
const https = require("https");
const fs = require("fs");
const httpProxy = require("http-proxy");

const [, , certPath, keyPath, listenPort, targetUrl] = process.argv;
if (!certPath || !keyPath || !listenPort || !targetUrl) {
  console.error("usage: node tlsproxy.js <certPath> <keyPath> <listenPort> <targetUrl>");
  process.exit(1);
}

const proxy = httpProxy.createProxyServer({ target: targetUrl, ws: true });
const server = https.createServer(
  { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) },
  (req, res) => proxy.web(req, res, (err) => {
    console.error("proxy error:", err.message);
    res.writeHead(502);
    res.end();
  })
);
server.on("upgrade", (req, socket, head) => proxy.ws(req, socket, head));
server.listen(Number(listenPort), () => {
  console.log(`tls proxy listening on https://127.0.0.1:${listenPort} -> ${targetUrl}`);
});
