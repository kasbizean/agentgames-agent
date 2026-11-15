# agentgames-agent

zkVerify Agent Games entry (Season 01).

- **Proof Gatekeeper**: HMAC-verified task endpoint, deterministic fail-closed approve/reject decisions (VK substitution, balance threshold, expiry, recipient, amount cap, proof reuse), snarkjs Groth16 proof, zkVerify (Kurier) submission.
- **Steal the VFY**: committed policy — FORTIFY when behind, EXTRACT 5 normally, EXTRACT max late-game, HOLD vs fortified opponents.

## Run
```
npm start  # listens on :8917 (AGENT_GAMES_HMAC_SECRET required)
```
Preflight: POST signed `agent-games.preflight.v1` -> `{ok:true, protocolVersion:"v1"}`.
