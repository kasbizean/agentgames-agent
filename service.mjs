// Agent Games endpoint — Proof Gatekeeper + Steal the VFY
import http from "http";
import crypto from "crypto";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const PORT = process.env.PORT || 8917;
function hmac(body){ return crypto.createHmac("sha256", SECRET).update(body).digest("hex"); }
function validSig(req, raw){
  const sig = req.headers["x-agent-games-signature"];
  if (!sig || !SECRET) return false;
  const a = Buffer.from(sig), b = Buffer.from(hmac(raw));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function signed(res, obj){
  const body = JSON.stringify(obj);
  res.writeHead(200, { "content-type": "application/json", "x-agent-games-signature": hmac(body) });
  res.end(body);
}
const seenProofs = new Set();
function gatekeeper(task){
  const i = task.input || {};
  if (i.registered_vk !== i.proof_vk) return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  if (BigInt(i.public_balance || 0) < BigInt(i.minimum || 0)) return { decision: "REJECT", reason_code: "BELOW_MINIMUM" };
  if (i.expiry_block && i.current_block && i.current_block >= i.expiry_block) return { decision: "REJECT", reason_code: "EXPIRED" };
  if (i.recipient !== i.condition_recipient) return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  if (BigInt(i.amount || 0) > BigInt(i.max_transfer || 0)) return { decision: "REJECT", reason_code: "AMOUNT_EXCEEDS_CAP" };
  if (i.proof_tx && seenProofs.has(i.proof_tx)) return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  if (i.proof_tx) seenProofs.add(i.proof_tx);
  return { decision: "APPROVE", reason_code: "ALL_CHECKS_PASS" };
}
function stealTurn(env){
  const s = env.state, turn = env.turn;
  const opp = Number(s.opponentBalance), me = Number(s.selfBalance);
  const oppFort = s.opponentFortifiedUntilTurn && turn <= s.opponentFortifiedUntilTurn;
  let action = { type: "EXTRACT", amount: 5 };
  if (opp > me + 10) action = { type: "FORTIFY" };
  else if (oppFort) action = { type: "HOLD" };
  else if (turn >= 16) action = { type: "EXTRACT", amount: Math.min(10, opp) };
  return { matchId: env.matchId, turn, action, agentTimestamp: new Date().toISOString(), idempotencyKey: crypto.randomUUID() };
}
const server = http.createServer((req, res) => {
  let chunks = [];
  req.on("data", c => chunks.push(c));
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8");
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, {"content-type":"application/json"});
      return res.end(JSON.stringify({ ok: true, service: "agent-games", ts: new Date().toISOString() }));
    }
    if (req.method !== "POST") { res.writeHead(404); return res.end(); }
    if (!validSig(req, raw)) { res.writeHead(401, {"content-type":"application/json"}); return res.end(JSON.stringify({ error: "bad signature" })); }
    let env; try { env = JSON.parse(raw); } catch { res.writeHead(400); return res.end(); }
    if (env.type === "agent-games.preflight.v1") return signed(res, { ok: true, protocolVersion: "v1" });
    if (env.type === "agent-games.proof-gatekeeper.v1") {
      const d = gatekeeper(env);
      if (d.decision === "APPROVE" && env.input) d.proof_tx = env.input.proof_tx;
      return signed(res, d);
    }
    if (env.matchId) return signed(res, stealTurn(env));
    return signed(res, { ok: true, received: env.type || "unknown" });
  });
});
server.listen(PORT, () => console.log(`agent-games on :${PORT}`));
