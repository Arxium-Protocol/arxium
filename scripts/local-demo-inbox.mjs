#!/usr/bin/env node
// Loopback SMTP inbox for Console manual tests. Delivers no external email.
import net from "node:net";
import http from "node:http";
import { writeFile } from "node:fs/promises";
const messages = [];
const home = process.env.DEMO_HOME;
const escape = text => String(text).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
net.createServer(socket => {
  let buffer = "", data = false, body = [], recipient = "", authLines = 0;
  socket.setEncoding("utf8"); socket.write("220 localhost local test inbox\r\n");
  socket.on("data", chunk => {
    buffer += chunk;
    for (;;) {
      const end = buffer.indexOf("\r\n"); if (end < 0) break;
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 2);
      if (data) {
        if (line !== ".") { body.push(line.startsWith("..") ? line.slice(1) : line); continue; }
        const raw = body.join("\r\n").replace(/=\r\n/g, "");
        const code = raw.match(/sign-in code is\s+(\d{6})/i)?.[1] ?? raw.match(/letter-spacing:8px[^>]*>(\d{6})/)?.[1] ?? "See raw message";
        messages.unshift({ recipient, code, received: new Date().toISOString(), raw });
        if (home) writeFile(`${home}/inbox.json`, JSON.stringify(messages, null, 2)).catch(console.error);
        console.log(`Local email captured for ${recipient}: ${code}`);
        data = false; body = []; socket.write("250 Message captured locally\r\n"); continue;
      }
      if (authLines) { authLines--; socket.write(authLines ? "334 UGFzc3dvcmQ6\r\n" : "235 Authentication successful\r\n"); continue; }
      const command = line.toUpperCase();
      if (command.startsWith("EHLO") || command.startsWith("HELO")) socket.write("250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1048576\r\n");
      else if (command.startsWith("AUTH PLAIN")) { if (line.split(" ").length > 2) socket.write("235 Authentication successful\r\n"); else { authLines = 1; socket.write("334 \r\n"); } }
      else if (command.startsWith("AUTH LOGIN")) { authLines = 2; socket.write("334 VXNlcm5hbWU6\r\n"); }
      else if (command.startsWith("RCPT TO:")) { recipient = line.slice(8).trim(); socket.write("250 OK\r\n"); }
      else if (command === "DATA") { data = true; body = []; socket.write("354 End with dot\r\n"); }
      else if (command === "QUIT") { socket.end("221 Bye\r\n"); }
      else socket.write("250 OK\r\n");
    }
  });
  socket.on("error", () => {});
}).listen(1025, "127.0.0.1", () => console.log("SMTP inbox listening on 127.0.0.1:1025"));
http.createServer((request, response) => {
  if (request.url === "/messages") { response.setHeader("Content-Type", "application/json"); response.end(JSON.stringify(messages)); return; }
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  response.end(`<!doctype html><title>Local Arxium test inbox</title><style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 20px}article{border-top:1px solid #ddd;padding:16px 0}code{font-size:28px}pre{white-space:pre-wrap}</style><h1>Local Console sign-in inbox</h1><p>Refresh after requesting a sign-in code. These messages stay on this machine.</p>${messages.map(m => `<article><p>${escape(m.recipient)} · ${escape(m.received)}</p><code>${escape(m.code)}</code><details><summary>Raw email</summary><pre>${escape(m.raw)}</pre></details></article>`).join("") || "<p>No emails yet.</p>"}`);
}).listen(8025, "127.0.0.1", () => console.log("Inbox UI: http://localhost:8025"));
