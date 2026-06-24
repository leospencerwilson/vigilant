# Runbook — Vigilant config push (review-gated, Safe Mode, dead-man rollback)

End-to-end lifecycle for pushing a RouterOS config change to a device through Vigilant.
This is the **only** sanctioned way to change a router from Vigilant, and it is
**device-pull of an approved job** — Vigilant never reaches into a router.

> ⚠️ The WCN MikroTik estate is **live production** (SSTP/L2TP for ~250 Allied/Cegedim/WCN
> sites + HSCN). Every push is high-impact. Review the `.rsc` before approval, pilot on a
> canary, and rely on the dead-man's-switch rollback. Never auto-apply.

---

## 0. Roles & policy (who approves)

Two-person rule for production:

- **Author** — engineer who writes the `.rsc` and creates the job (`status='draft'`,
  `created_by`). Cannot approve their own job for production targets.
- **Approver** — a second engineer (currently: Jake, or the on-call senior network
  engineer) who reviews the `.rsc` and sets `status='approved'` (`approved_by`). For
  changes to the core WCN router, flag in `/system note` first (per
  `server project/CLAUDE.md`).
- **Confirmer** — whoever is watching the rollout confirms the device is healthy within
  the confirm window. Usually the Author. If no one confirms, the change auto-reverts.

Every transition is written to `audit_log` (actor + action + serial). No job is ever
served to a device unless it is `approved` and targeted at that device (by `device_id` or
`target_tag`), and the device verifies the checksum before importing.

---

## 1. Lifecycle at a glance

```
 draft ──approve──▶ approved ──device fetch──▶ fetched ──device import──▶ applying
   │                   │                                                     │
 (author)          (approver)                                    ┌──────────┴──────────┐
                                                          confirm│                     │no confirm
                                                                 ▼                     ▼
                                                             applied            rolled_back
                                                                                       │
                                                                    (import error / disconnect / failed) ─▶ failed
```

`config_jobs.status` values (schema): `draft`, `approved`, `fetched`, `applying`,
`applied`, `failed`, `rolled_back`, `cancelled`.

---

## 2. Step by step

### 2.1 Author the `.rsc` (draft)

In Watchman / via the action API, create a `config_jobs` row:

- `kind` = `snippet` (a focused change — preferred) or `full`.
- `rsc_text` = the exact RouterOS 7 commands. Keep it **minimal and reversible**; assume
  it runs under Safe Mode (a dropped session reverts it).
- `rsc_sha256` = sha256 of `rsc_text` (the device re-checks this before import;
  `transform.sha256Hex`).
- `device_id` (single device) **or** `target_tag` (group). Use `is_canary=true` to target
  one device first.
- `confirm_window_s` = dead-man's-switch keep-window (default **300s** / 5 min).
- `created_by` = the author.

Status starts `draft`. **A draft is never served.**

Authoring guidance:
- Prefer additive / `set` changes you can undo; avoid `/system reset-configuration`.
- Do not include secrets in `rsc_text` (it is stored and fetched in cleartext over TLS).
- Test the snippet on a lab router first where possible.

### 2.2 Approve (two-person)

A second engineer reviews `rsc_text`, then sets `status='approved'`, `approved_by`,
`approved_at`. Only now will the ingest serve it. For a group job, consider approving the
**canary** first and promoting later (2.6).

### 2.3 Pickup (device pull)

On its next agent tick the device calls `POST /telemetry`. If `getPendingConfigJob` finds
an `approved` job targeting it, the response includes:

```jsonc
"job": { "id":"<uuid>", "sha256":"…", "url":"https://vigilant…/config/<id>.rsc", "confirm_window_s":300 }
```

The agent then `/tool fetch`es `url`. The ingest serves `rsc_text` with the checksum in the
`X-Vigilant-Sha256` header and (via `markConfigJob`) sets `status='fetched'`, `fetched_at`.
The ingest verifies the job targets this device before serving — a device can never pull
another device's job.

### 2.4 Apply safely (on the device)

The agent (`agent/vigilant-agent.rsc`, config-job APPLY path) does, in order:

1. **Checksum gate** — recompute sha256 of the fetched body; **abort** if it does not equal
   `X-Vigilant-Sha256`. Nothing is applied on mismatch.
2. **Pre-snapshot** — `/export` to `vigilant-pre-<jobid>.rsc` and a binary `/system backup`.
   The export is POSTed back as the rollback point.
3. **Arm the dead-man's switch** — a `/system scheduler` entry that, after
   `confirm_window_s`, re-imports the pre-snapshot and removes itself. This is what
   recovers the device if the change breaks management access.
4. **Import** — `/import` the new `.rsc`. This behaves like **Safe Mode**: if the import
   errors or the session drops, RouterOS reverts the in-progress changes.
5. **Report** — `POST /config/result` with `{job_id,status,result_log,export?}`. The ingest
   records the result and snapshots (pre/post). Status moves to `applying` → and to
   `failed` if the import errored.

### 2.5 Confirm or auto-rollback

- The device re-checks in on its next tick. The **Confirmer** verifies health in Watchman
  (link up, PPP sessions back, no new alerts) **within `confirm_window_s`**.
- **Confirmed:** the operator confirms in Watchman; on the device's next pull Vigilant
  signals "cancel rollback", the agent removes the dead-man scheduler, and the job becomes
  `applied` (`applied_at`). Only the server's confirmation cancels the rollback.
- **Not confirmed (or device lost management):** the dead-man scheduler fires, re-imports
  the pre-snapshot, and the device self-recovers. The job ends `rolled_back`. The agent
  reports this via `POST /config/result` on its next successful check-in.

### 2.6 Canary → group promotion

For a `target_tag` job, target one device with `is_canary=true` first. Only after the
canary reports `applied` **and** stays healthy for the confirm window do you promote the
job to the rest of the tag (approve/release the group job). Never approve a fleet-wide push
without a green canary.

---

## 3. How to roll back

There are three rollback layers — they stack from automatic to manual:

1. **Automatic (dead-man's switch).** Default. If no confirm within `confirm_window_s`, or
   if management access is lost, the scheduler re-imports the pre-snapshot. No human action
   needed. Job → `rolled_back`.
2. **Safe Mode.** During `/import`, a dropped session or import error reverts the
   in-progress changes immediately (before the dead-man window even matters). Job → `failed`.
3. **Manual.** If a change applied, confirmed, then later proved bad, re-push the
   pre-change export as a **new** review-gated job:
   - take the most recent `config_snapshots` row for the device with `source='pre-apply'`
     (the export captured in 2.4 step 2);
   - create a new `config_jobs` draft with that text, approve it, and let the device pull
     and apply it through the same Safe-Mode + dead-man path.
   - For a device you can reach (office VPN / Winbox), you may instead `/import` the
     pre-snapshot directly under Safe Mode (`Ctrl-X`) — reviewed, never blind.

Emergency on-box recovery (if Vigilant is unreachable): connect via Winbox/SSH
(`192.168.100.240` for the core, or the site's mgmt path), enter Safe Mode (`Ctrl-X`), and
`/import vigilant-pre-<jobid>.rsc` or restore the `/system backup` taken pre-apply. The
pre-snapshot files are left on the router by the agent for exactly this.

---

## 4. Server-side guarantees (non-negotiable)

- The ingest serves **only** `status='approved'` jobs, **only** to the targeted device,
  **only** after the device verifies the checksum. No server-side auto-apply.
- A malformed job or result must not 500 the service or affect other devices (fail safe).
- Tokens / secrets are never logged; the bearer is hashed before lookup.
- Every state change is audited (`audit_log`).

## 5. Failure cheatsheet

| Symptom | Status | What happened | Action |
|---|---|---|---|
| Device never fetched | stuck `approved` | offline, or not targeted | check `device_state.status`; confirm `device_id`/`target_tag` |
| `failed` right after fetch | `failed` | checksum mismatch or import error | inspect `result_log`; re-author; Safe Mode caught it |
| `rolled_back` | `rolled_back` | no confirm in window / lost mgmt | device self-recovered; review why the change broke access |
| Applied but bad | `applied` | confirmed too early | manual rollback (§3.3) via new job from `config_snapshots` |
