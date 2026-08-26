'use strict';

// Vigilant — the PMR control plane's CLOSED VERB ALLOWLIST, the per-verb argument specs, and
// the intended-state field table. Every layer that creates or serves a job goes through this
// file, and nothing that is not in this file can ever be handed to an executor.
//
// ── THE VERB RULE, which is law ──────────────────────────────────────────────
// The server sends a NAME. The executor looks that name up in ITS OWN table and decides what
// it means locally. The server never sends a command line, so a compromised or mistaken
// server cannot turn this channel into arbitrary execution on a pharmacy counter or a
// Proxmox node hosting live pharmacy desktops.
//
// This is the same pair PI_ACTIONS/ACTIONS already forms for the one-shot service actions —
// handlers.js holds the server half, the Pi agent holds the device half — and it is extended
// here rather than replaced, because that pair has no job ladder: an action has no ack, no
// confirmation and no time limit, and this control plane needs all three.
//
// ── ARGUMENTS ARE DATA, AND BOUNDED DATA ─────────────────────────────────────
// Every `args` entry is a bool, an enum or a range-checked integer. There is no free-text
// argument anywhere in this table and there must never be one: counterSettings.js states the
// reason for the settings channel and it applies verbatim here — these values end up as argv
// on a machine in a pharmacy, and "the refusal is what makes the file safe to write, not the
// quoting at the far end". An executor is expected to RE-VALIDATE against the same pattern
// before an argument becomes argv, the way the relay re-checks its session target and
// test-print re-checks its queue name.
//
// ── DONE MEANS PROVEN, AND "PROVEN BY WHOM" IS A SEPARATE QUESTION ───────────
// Every verb names a `confirm` rule: a reading, taken AFTER the job was applied, that shows
// the world actually changed. A verb with no confirming reading is NOT ADMITTED — see
// UNADMITTED_VERBS at the foot of this file for the one that is currently refused and
// exactly what would admit it.
//
// ⚠️ EVERY VERB IN THIS TABLE IS TODAY CONFIRMED BY ITS OWN EXECUTOR. Not just the two
// counter verbs — all seven. The block above SELF_ATTESTATION at the foot of this file works
// through each one and says whether that is acceptable and what an independent reading would
// be. It is written out rather than glossed because a confirmation that only looks
// independent is worse than one that admits it is not.
//
// ── CONVERGENCE ──────────────────────────────────────────────────────────────
// `converges` is true only for a field that is a CONFIGURATION property, is fully
// reversible, interrupts no session, and is confirmed by a FRESH reading rather than by an
// exit code. Those four together are what makes it safe for a reconciler to close the gap
// unattended, with nobody watching. 'onboot' converges. 'running' never does — power is a
// LIFECYCLE property and a lifecycle change is a one-shot job with a time limit that an
// operator asked for.
//
// ⚠️ The fourth condition used to read "a fresh INDEPENDENT reading". It was not true of
// onboot and is not true of anything in this table — see SELF_ATTESTATION below. What
// carries the weight for a converging verb is the first three: a reconciler that loops on a
// self-attested reading of a non-disruptive, reversible configuration property can at worst
// believe a flag is set when it is not. The same loop on a disruptive verb would be a
// counter restarted forever, which is why `converges` is only ever true where `disruptive`
// is false.

// ── argument specs ───────────────────────────────────────────────────────────
// Shaped like counterSettings.SPECS on purpose: same three types, same closed-whitelist
// treatment, same refusal-not-coercion rule. `resolved: true` marks a value the SERVER
// computes and OVERWRITES — a caller may pass it, and it will be thrown away.
const ARG_SPECS = {
  // Proxmox VMIDs in this estate. Bounded because it becomes an argument to `qm` on a node
  // that hosts live pharmacy desktops.
  vmid:   { type: 'int', min: 100, max: 999999, resolved: true },
  // 1|0, not true|false: it is what the Proxmox config key holds and what the collector
  // reads back, so the confirming comparison is against the same vocabulary.
  onboot: { type: 'enum', values: [0, 1] },
};

// ── the allowlist ────────────────────────────────────────────────────────────
// Keys are the verb names. Nothing outside this object can be created, claimed or served.
//
//   executor            which outward-polling executor picks it up. There are exactly two,
//                       and both ride a reply to a call they ALREADY make: the Pi's
//                       POST /telemetry and the Proxmox collector's POST /proxmox/report.
//                       No third executor and no inbound path.
//   disruptive          does executing this interrupt a session? The ONE input to the hours
//                       gate. Answer it pessimistically: a verb marked non-disruptive by
//                       mistake is a pharmacist signed out mid-consultation.
//   converges           may a reconciler close this gap unattended? See the four conditions
//                       above. Only ever true where `disruptive` is false.
//   retry_ok            may a claim whose visibility window lapsed be handed out AGAIN? The
//                       same distinction claimRelayRequest draws with method IN
//                       ('GET','HEAD'): re-handing out a shutdown is not free.
//   confirm             the named reading that proves it worked. Implemented as one
//                       set-based statement per kind in store.pg.js confirmPmrJobs().
//   confirm_self_attested
//                       is that reading authored by the same executor that ran the job?
//                       TRUE on every verb here today. Carried per row so nothing can
//                       quietly forget, and so the UI can label a 'confirmed' job honestly.
//   confirm_independent_would_be
//                       the reading that WOULD be independent, named concretely enough to
//                       build. This is the specification for taking the flag off.
//   self_attested_acceptable_because
//                       why shipping it self-attested is defensible for THIS verb. Not a
//                       blanket excuse: two of the seven say plainly that it is a weakness.
//   confirm_deadline_s  how long that reading has to appear before the job FAILS. Sized to
//                       the reading's own cadence, not to the work: the Proxmox collector
//                       ticks every 15 minutes and its timer carries an explicit
//                       do-not-shorten warning, so anything confirmed from proxmox_vms needs
//                       room for two ticks plus the randomised delay.
//   ttl_s               how long an UNCLAIMED job stays claimable before it expires. A
//                       session restart queued at midnight must not go off at 09:20 because
//                       a Pi came back late — expiring is the correct outcome, not firing.
//                       ⚠️ For a job the hours gate is holding, the clock starts when the
//                       gate OPENS, not when the row was written — see not_before in
//                       store.pg.js createPmrCounterJob. A 90-minute TTL and a promise that
//                       the job applies overnight cannot both be true of the same row.
//   claim_ttl_s         the visibility timeout on a claim.
//   max_attempts        how many times the job may be handed to an executor AT ALL. retry_ok
//                       says a lapsed claim MAY be re-offered; this says how often. Without
//                       it, retry_ok plus a short claim TTL is a repeating sign-out loop.
//   args                the closed per-verb argument whitelist.
//   executor_note       what the executor's own table must map this name to. This is the
//                       contract the agent-side build implements; it is documentation here
//                       and a command line NOWHERE.
const VERBS = {
  // ── counter-pi verbs — ride the reply to POST /telemetry ──────────────────
  'counter.session-restart': {
    executor: 'counter-pi',
    // The whole point of the verb: it signs the member of staff out. Never unattended in
    // hours. This is the verb the nightly restart is built from.
    disruptive: true,
    converges: false,
    // Safe to hand out again: the session it would restart has already gone. A duplicate
    // restart at 00:05 costs nothing; a restart that never happened costs a morning.
    //
    // ⚠️ 'Again' is not 'forever'. retry_ok with a 120-second claim TTL inside a 5400-second
    // life and no cap is forty-five sign-outs, which is a loop and not a retry — see
    // max_attempts, which the claim query enforces as a predicate (B3).
    retry_ok: true,
    max_attempts: 3,
    confirm: 'pi-session-restarted',
    // ⚠️ SELF-ATTESTED. See SELF_ATTESTATION at the foot of this file. The confirming
    // reading comes out of device_state.raw, which the Pi — the executor — authored.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the Proxmox collector reporting a per-VM interactive-session count from the guest '
      + 'agent (agent/get-users), so the sign-out is proven by the desktop VM\'s own session '
      + 'count reaching zero and rising again in a reading taken by a different collector on '
      + 'a different box',
    self_attested_acceptable_because:
      'the safety property does not rest on the confirmation. What must never happen — a '
      + 'session restart during opening hours, unattended — is enforced by '
      + 'pmr_disruptive_allowed() in the CLAIM, before the job reaches a Pi, and no reading '
      + 'is an input to it. The reading is also a TRANSITION (a session start after '
      + 'applied_at, or a down-then-up pair across two ticks), not a field an agent can '
      + 'assert once, and an unproven job FAILS into the pre-opening check, which puts a '
      + 'person in front of the counter before the pharmacy opens.',
    confirm_deadline_s: 900,
    ttl_s: 5400,
    claim_ttl_s: 120,
    args: {},
    executor_note:
      'restart the kiosk session so the RDP session signs out and back in — the Pi maps this '
      + 'name to its own local unit restart, exactly as ACTIONS maps "restart-kiosk"',
  },

  'counter.reboot': {
    executor: 'counter-pi',
    disruptive: true,
    converges: false,
    retry_ok: false,   // a reboot re-offered to a Pi that took the first one is a boot loop
    max_attempts: 1,
    confirm: 'pi-uptime-reset',
    // ⚠️ SELF-ATTESTED — device_state.uptime_s is the Pi's own reading of itself.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the WireGuard hub\'s own view of the peer: wg_peers.latest_handshake for this Pi\'s '
      + 'public key going stale and then renewing after applied_at. The hub is not the Pi '
      + 'and the collector that writes wg_peers is not the agent, so a Pi that ignored the '
      + 'reboot cannot produce that pair.',
    self_attested_acceptable_because:
      'the same claim-time gate argument as counter.session-restart, plus the reading is a '
      + 'MONOTONIC counter compared against wall time (uptime_s shorter than the age of the '
      + 'job), not a self-report of success. An agent would have to lie about its own '
      + '/proc/uptime to fake it. The independent reading above is cheap and already '
      + 'collected — this flag should come off first.',
    confirm_deadline_s: 900,
    ttl_s: 5400,
    claim_ttl_s: 300,
    args: {},
    executor_note: 'reboot the thin client — the Pi maps this name locally, as ACTIONS maps "reboot"',
  },

  // ── the printer table's APPLY verb (§4 of docs/pmr-printer-contract.md) ────
  // "Building or sharing a CUPS queue reaches the counter AT ONCE and interrupts nobody.
  //  Adding or removing a **Windows** printer needs a session restart, which signs the user
  //  out. So: a printer change stages, and Watchman shows 'applies at midnight' with an
  //  apply-now button that states it signs the member of staff out. `printing-promote` is the
  //  named verb that swaps the staged table live and restarts the session as ONE action."
  //
  // The server writes the queue table; the telemetry reply carries it; the agent renders it to
  // printers.tab.NEXT and stops. Nothing on that path touches a session. THIS is the step that
  // does, and it is on the job ladder rather than in ACTIONS for the reason the ladder exists:
  // it needs the hours gate, an ack, a time limit and a confirming reading, and an `action`
  // has none of the four.
  //
  // ⭐ THE NAME IS THE DEVICE'S OWN. wcn-toolbox-priv already implements a privileged verb
  // called exactly `printing-promote` — it validates .next against the same §2 rules, keeps
  // .prev, swaps the live file and restarts the session as one action. This entry does not
  // invent a mechanism; it gives the existing device verb a route from Watchman.
  'counter.printing-promote': {
    executor: 'counter-pi',
    // It restarts the kiosk session, which signs the member of staff at that counter out.
    // Identical cost to counter.session-restart, and it gets the identical treatment.
    disruptive: true,
    converges: false,
    // ⛔ NEVER re-offered. counter.session-restart may be re-handed out because "the session it
    // would restart has already gone" — that argument does NOT hold here. The first promotion
    // already swapped .next onto the live file, so a second offer is a second sign-out that
    // changes nothing, and .prev is consumed by it. A promote that was handed out and never
    // reported must reach its deadline and FAIL into the pre-opening check, which puts a
    // person in front of the counter before the pharmacy opens.
    retry_ok: false,
    max_attempts: 1,
    confirm: 'pi-printers-promoted',
    // ⚠️ SELF-ATTESTED, exactly like the two verbs above it — the reading comes out of
    // device_state.raw -> 'peripherals', which the Pi authored. See SELF_ATTESTATION below.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the desktop VM\'s own view of its redirected printers — the Proxmox collector reading '
      + 'the guest\'s installed printer list through the guest agent, so a queue appearing '
      + 'inside Windows is proven by a reading taken on a different box from the Pi that '
      + 'promoted it. That is also the only reading that proves the thing an operator '
      + 'actually asked for, because §1 says the queue name IS the Windows printer name.',
    self_attested_acceptable_because:
      'the same claim-time argument as counter.session-restart — the hours gate is applied in '
      + 'the CLAIM, before the job reaches a Pi, and no reading is an input to it — plus the '
      + 'reading is a TRANSITION rather than an assertion: print_tab_pending is observed TRUE '
      + 'while the job is in flight (stamped on pmr_jobs.print_tab_staged_at by the telemetry '
      + 'hot path, not by anything the executor says) and FALSE in a later reading taken after '
      + 'the job was applied, and the Pi computes the flag by comparing two files it does not '
      + 'choose the contents of. Both halves are predicates of the confirm statement in '
      + 'store.pg.js — the TRUE half was for a time only a claim in this comment (B2), which '
      + 'is why it is now named with the column that carries it. A promote that cannot be '
      + 'proven FAILS, and a failed counter job raises that counter in the pre-opening check.',
    confirm_deadline_s: 900,
    ttl_s: 5400,
    claim_ttl_s: 300,
    args: {},
    executor_note:
      'promote the staged printer table and restart the session as ONE action — the Pi maps '
      + 'this name to its own `wcn-toolbox-priv printing-promote`, which re-validates '
      + 'printers.tab.next against §2, keeps printers.tab.prev, swaps the live file and '
      + 'restarts the kiosk. The server sends the NAME; it never sends a table on this path '
      + 'and never names a file.',
  },

  // ── proxmox-node verbs — ride the reply to POST /proxmox/report ────────────
  'vm.set-onboot': {
    executor: 'proxmox-node',
    // A CONFIGURATION property. It changes what happens at the NEXT node boot and touches
    // nothing that is running, so it interrupts no session and is fully reversible by
    // setting it back. This is the canonical converging verb: onboot is 0 on every Windows
    // desktop in the estate today, including sites that trade on them, so a node reboot
    // leaves a pharmacy with a gateway and no desktops.
    disruptive: false,
    converges: true,
    retry_ok: true,     // idempotent — setting onboot to the value it already has is a no-op
    max_attempts: 3,
    confirm: 'vm-onboot-matches',
    // ⚠️ SELF-ATTESTED, and this was the false claim (D5). proxmox_vms is written by
    // POST /proxmox/report — the same request, from the same collector process, on the same
    // node, that was handed this job and posted its result. Even the freshness test
    // `v.seen_at > j.applied_at` compares two timestamps that node authored.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the VM config lives on /etc/pve, the cluster filesystem, so ANOTHER node in the '
      + 'cluster genuinely sees this VM\'s onboot flag without the executing node in the '
      + 'path. Confirming from a proxmox_vms row whose reporting node is NOT the node that '
      + 'ran the job would be a real independent reading and needs no new collector — only '
      + 'a reported_by_node column on proxmox_vms and one extra predicate here.',
    self_attested_acceptable_because:
      'this is the least dangerous verb in the table: non-disruptive, fully reversible, and '
      + 'the only one allowed to converge unattended. The worst outcome of a false confirm '
      + 'is that an onboot flag is believed set when it is not, which surfaces the next time '
      + 'a node reboots without its desktops — bad, but not a person signed out. It is also '
      + 'the verb whose independent reading is nearest to hand (see above).',
    // Two collector ticks plus its RandomizedDelaySec. The timer is 15 minutes and must not
    // be shortened, so the deadline stretches to the reading rather than the reading to it.
    confirm_deadline_s: 2400,
    ttl_s: 86400,
    claim_ttl_s: 1800,
    args: { vmid: ARG_SPECS.vmid, onboot: ARG_SPECS.onboot },
    executor_note: 'set the VM\'s onboot flag on this node',
  },

  'vm.start': {
    executor: 'proxmox-node',
    // Starting a stopped VM interrupts nothing — there is no session to lose.
    disruptive: false,
    // LIFECYCLE, so it NEVER converges however harmless it looks. Power is a one-shot job
    // with a time limit that somebody asked for: a reconciler that starts VMs unattended
    // would fight an engineer who has just stopped one, and would restart a VM somebody
    // powered down for a reason nobody wrote down.
    converges: false,
    retry_ok: true,     // starting a running VM is a no-op
    max_attempts: 3,
    confirm: 'vm-status-running',
    // ⚠️ SELF-ATTESTED — proxmox_vms.status is written by the same node that ran the start.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the counter Pi is the only thing in this platform that talks to a desktop VM from '
      + 'outside the node. Its telemetry already carries rdp.running and the target it is '
      + 'connected to, so a Pi whose configured_target is this VM reporting rdp.running true '
      + 'after applied_at is a reading of the guest taken by a different machine on a '
      + 'different network path. It needs no new agent field.',
    self_attested_acceptable_because:
      'starting a stopped VM interrupts nothing, so a false confirm cannot harm anybody at a '
      + 'counter — it can only leave a desktop believed up when it is down, which the '
      + 'pre-opening check catches from the Pi\'s side before the pharmacy opens.',
    confirm_deadline_s: 2400,
    ttl_s: 7200,
    claim_ttl_s: 1800,
    args: { vmid: ARG_SPECS.vmid },
    executor_note: 'start the VM on this node',
  },

  'vm.shutdown': {
    executor: 'proxmox-node',
    // A graceful shutdown takes the desktop down with whoever is signed into it.
    disruptive: true,
    converges: false,
    retry_ok: false,    // a re-offered shutdown can land on a VM somebody has just started
    max_attempts: 1,
    confirm: 'vm-status-stopped',
    // ⚠️ SELF-ATTESTED, AND HERE IT IS A REAL WEAKNESS — see below.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the counter Pi that boots into this VM reporting that it can NO LONGER reach the '
      + 'desktop after applied_at (rdp.running false against this configured_target), '
      + 'followed by the node reporting stopped. Absence proven from the far end of the wire '
      + 'is the reading that the node itself cannot fake.',
    self_attested_acceptable_because:
      'IT IS NOT, ON ITS OWN MERITS. This is a POWER verb: it takes a live pharmacy desktop '
      + 'down with whoever is signed into it, and the only thing that says it happened is '
      + 'the box that did it. What makes it shippable is that nothing about the SAFETY '
      + 'property depends on the confirmation — the hours gate runs in the claim, '
      + 'max_attempts is 1 and retry_ok is false, so a job that is never proven is never '
      + 're-offered — and the failure direction is a job that FAILS and raises a person. '
      + 'The confirmation is an audit statement here, not a control. Treat it as such until '
      + 'the reading above exists.',
    confirm_deadline_s: 2400,
    ttl_s: 7200,
    claim_ttl_s: 1800,
    args: { vmid: ARG_SPECS.vmid },
    executor_note: 'graceful guest shutdown of the VM on this node',
  },

  'vm.reboot': {
    executor: 'proxmox-node',
    disruptive: true,
    converges: false,
    retry_ok: false,
    max_attempts: 1,
    confirm: 'vm-uptime-reset',
    // ⚠️ SELF-ATTESTED, and a power verb — the same standing as vm.shutdown.
    confirm_self_attested: true,
    confirm_independent_would_be:
      'the counter Pi booted into this VM observing its RDP session drop and come back after '
      + 'applied_at — the down-then-up pair the counter verbs already use, but read against '
      + 'the VM rather than against the Pi. Same field, different subject, no new collector.',
    self_attested_acceptable_because:
      'weaker than it looks, but better than vm.shutdown: the reading is a monotonic uptime '
      + 'compared against wall time, so a node that ignored the reboot and reported "running" '
      + 'still does not confirm it. The rest of the vm.shutdown argument applies verbatim — '
      + 'max_attempts 1, retry_ok false, the hours gate in the claim, and failure towards a '
      + 'person.',
    confirm_deadline_s: 2400,
    ttl_s: 7200,
    claim_ttl_s: 1800,
    args: { vmid: ARG_SPECS.vmid },
    executor_note: 'graceful guest reboot of the VM on this node',
  },
};

const VERB_NAMES = Object.keys(VERBS);
const EXECUTORS = ['counter-pi', 'proxmox-node'];
const CONFIRM_KINDS = Array.from(new Set(VERB_NAMES.map((v) => VERBS[v].confirm)));

// Statuses an EXECUTOR may report. A subset of the pmr_jobs.status CHECK set, and the
// important word is the one that is NOT in it: 'confirmed'. An executor can say it ran the
// thing; it can never say the thing is true. That is the whole difference between 'applied'
// and 'confirmed', and putting it in a closed set here means a malformed body cannot violate
// the DB CHECK and 500 the service either. Mirrors DEVICE_REPORTABLE_STATUSES in handlers.js.
const EXECUTOR_REPORTABLE_STATUSES = new Set(['applied', 'failed']);

// ── WHAT AN EXECUTOR MUST UNDERSTAND BEFORE IT IS OFFERED A JOB ──────────────
// ⚠️ HANDING A JOB OUT IS THE CLAIM. There is no ack: the job goes out on the reply to a
// poll and is 'claimed' the moment it is selected. So an executor that does not understand
// the key SWALLOWS the job — it goes pending -> claimed -> expired, silently, and the
// pre-opening check then emails "counters may not open" for a healthy counter (S10).
//
// The shipped Pi agent (agent/pi/vigilant-pi-agent.py) reports "agent_version": 1 and has NO
// pmr_job branch — it does not read the key at all. With the control plane switched on, EVERY
// nightly restart at EVERY live site would be swallowed that way, and the estate would get an
// outage email every night on the one channel reserved for real outages.
//
// So the claim is gated on the executor's own reported version reaching the version that
// implements the key. An un-upgraded executor sees NO jobs, which is the correct direction:
// a job that is never offered stays pending and shows as waiting, and nothing is lost.
//
// ⚠️ RAISING THIS NUMBER IS THE SECOND HALF OF SHIPPING THE AGENT-SIDE BRANCH. The agent
// build that adds `pmr_job` must report agent_version 2 in its telemetry payload; until a Pi
// does, it is offered nothing. The version is read from device_state.raw->>'agent_version',
// which is the agent's own claim about itself — that is acceptable here because the failure
// direction is "a capable agent is not offered work", never "an incapable one is".
const PMR_JOB_AGENT_VERSION = 2;

// ── THE SAME FLOOR, FOR THE OTHER EXECUTOR (D4) ──────────────────────────────
// The Proxmox node path had the hours gate and the attempts cap but NO capability floor, so
// it was one PROXMOX_NODE_TOKENS entry away from the exact failure S10 describes on the Pi
// side. The SHIPPED collector (collectors/vigilant-proxmox-collector.py) posts
// {"vms", "capacity"} and parses no `jobs` key at all — so the first per-node token issued
// to it would have made vm.shutdown and vm.reboot jobs vanish silently: claimed on the
// reply, never executed, never reported, expired at their deadline. Claimed-and-lost is the
// worst of the three outcomes, because it looks like work in flight.
//
// So the collector reports `collector_version` at the top level of POST /proxmox/report and
// is offered nothing below this number. It is the collector's own claim about itself, the
// same as the Pi's agent_version, and acceptable for the same reason: the failure direction
// is "a capable collector is offered no work", never "an incapable one is".
//
// ⚠️ RAISING THIS IS THE SECOND HALF OF SHIPPING THE COLLECTOR-SIDE BRANCH. The build that
// learns to read `jobs`, run the verb from its own local table, and post `job_results` must
// report collector_version 2. Until one does, no node receives a job however many tokens are
// issued.
const PMR_JOB_COLLECTOR_VERSION = 2;

// ── ⛔ THE FLOOR, FOR EVERY CHANNEL THAT CAN RESTART A KIOSK (A4) ─────────────
// PMR_JOB_AGENT_VERSION above protected ONE key. The telemetry reply carries five more
// directives, and three of them end in a session restart on the SHIPPED agent_version 1
// agent, with no floor of any kind. So "the control plane is inert until the executors ship"
// was true of pmr_job and of nothing else, and the comment saying it was doing real work in
// a reader's head that no code was doing on the wire.
//
// THE CHOICE, AND IT IS A CHOICE: the floor is EXTENDED to every channel that can restart a
// kiosk, rather than each being argued safe in a comment. One table, read by the telemetry
// handler, so the question "what does a device have to be running before we send it this"
// has one answer per channel in one place — and adding a sixth directive means adding a row
// here or deliberately writing down why it needs none.
//
// ⚠️ WHAT A FLOOR ACTUALLY BUYS is different per channel, and the numbers say so:
//
//   pmr_job   AT-MOST-ONCE — handing it out IS the claim, there is no ack. An agent that
//             cannot parse it SWALLOWS the job: pending -> claimed -> expired, with nothing
//             having happened and the pre-opening check emailing about a healthy counter.
//             Floor 2, because no shipped build implements the key at all.
//   action    ALSO AT-MOST-ONCE. takeCounterAction() CLEARS pending_action on delivery, so
//             an agent that ignores `action` loses a queued reboot silently — the same
//             failure as pmr_job. The floor is checked BEFORE the take, never after, or the
//             floor itself would be what discards it.
//   boot,     Re-sent on EVERY tick and self-healing, so a lost one costs nothing; these are
//   settings  floored for the other half of the reason — an unidentified executor must not
//             be handed a directive that restarts a pharmacy counter's session. A device
//             that has not said what it runs is offered neither, and starts receiving both
//             the moment it reports a version.
//
// ⚠️ AND THE THREE THAT ARE DELIBERATELY UNFLOORED, which is the other half of the choice:
//
//   printers  writes printers.tab.NEXT and stops. §2 of the printer contract is explicit that
//             nothing on that path touches a live session; the swap is counter.printing-
//             promote, which is a pmr_job and therefore already behind floor 2.
//   relay     opens a viewer onto the existing display. It starts no session and ends none.
//   branding  a splash image, a console banner and a kiosk message. Cosmetic by construction
//             — brandingDirective() carries no session field — and a floor would only mean a
//             counter shows the wrong logo.
// All three are re-sent every tick, so an agent that cannot read them loses nothing either.
//
// The version is the DEVICE'S OWN CLAIM about itself, out of the telemetry body it already
// posts — the same trust, and the same reason it is acceptable, as the pmr_job floor: the
// failure direction is "a capable agent is offered no work", never "an incapable one is".
// A device that reports nothing yields null, and null meets no floor.
//
// ⚠️ 1 IS NOT A NO-OP. The shipped agent implements apply_settings, apply_boot_target and
// run_action and reports agent_version 1, so the estate is unaffected — but a device that has
// never reported, or reports a malformed version, is now offered none of the three instead of
// all of them.
const COUNTER_CHANNEL_AGENT_FLOOR = Object.freeze({
  boot: 1,
  settings: 1,
  action: 1,
  pmr_job: PMR_JOB_AGENT_VERSION,
});

// The version an executor claims, as an integer, or null. Kept here rather than inline at the
// call site so the PARSE is shared with the floor it is compared against: a string "1" is
// accepted (the wire is JSON written by five different owners), "1.2", "v1" and "" are not,
// and anything unparseable is null — which meets no floor.
function reportedAgentVersion(value) {
  if (Number.isInteger(value)) return value >= 0 ? value : null;
  if (typeof value === 'string' && /^\d{1,9}$/.test(value.trim())) return Number(value.trim());
  return null;
}

// Does this executor meet the floor for this channel? An unknown channel is REFUSED rather
// than waved through, on the same closed-whitelist reasoning as every other table in this
// file: a directive nobody has decided about must not default to "send it".
function agentMeetsFloor(version, channel) {
  if (!Object.prototype.hasOwnProperty.call(COUNTER_CHANNEL_AGENT_FLOOR, channel)) return false;
  const v = reportedAgentVersion(version);
  return v !== null && v >= COUNTER_CHANNEL_AGENT_FLOOR[channel];
}

// ── ⚠️ EVERY VERB HERE IS SELF-ATTESTED. ALL SEVEN. ──────────────────────────
// "DONE MEANS PROVEN" originally said 'confirmed' is a SEPARATE reading, from a table some
// OTHER collector wrote. That was true of no verb in this table, and a previous pass made it
// half-honest: it declared the two counter verbs self-attested (correctly) and then asserted
// — in a test, which is the worst place to put a false claim — that the four Proxmox verbs
// are confirmed independently. They are not. This is the correction (D5).
//
//   pi-session-restarted  reads device_state.raw -> 'rdp'.          The Pi agent wrote it.
//   pi-uptime-reset       reads device_state.uptime_s.              The Pi agent wrote it.
//   pi-printers-promoted  reads device_state.raw -> 'peripherals'.  The Pi agent wrote it.
//   vm-onboot-matches     reads proxmox_vms.onboot.  \
//   vm-status-running     reads proxmox_vms.status.   |  ALL written by POST /proxmox/report
//   vm-status-stopped     reads proxmox_vms.status.   |  — the same request, from the same
//   vm-uptime-reset       reads proxmox_vms.uptime_s. /     collector process, on the same
//                                                          node, that was handed the job.
//
// The freshness test that reads like independence — `v.seen_at > j.applied_at` in
// confirmPmrJobs() — is a comparison of two timestamps THAT NODE AUTHORED. A node that ran
// nothing and reported anyway would satisfy it.
//
// ⚠️ 'INDEPENDENT' IS NOT WIDENED TO MAKE THE CODE PASS. A different table is not a
// different observer; a different process on the same box is not a different observer. The
// test for independence used here is: could the machine that executed the job produce this
// reading without the world having changed? If yes, it is self-attested.
//
// WHAT MAKES THE TABLE SHIPPABLE ANYWAY, and it is one argument, not six:
//
//   1. THE SAFETY PROPERTY DOES NOT DEPEND ON THE CONFIRMATION. What must never happen is a
//      disruptive job during opening hours, unattended. That is enforced by
//      pmr_disruptive_allowed() in the CLAIM statement — before the job ever reaches an
//      executor — and no reading, self-attested or not, is an input to it. A weak
//      confirmation cannot sign anybody out.
//   2. THE FAILURE DIRECTION IS TOWARDS A HUMAN. An unproven job FAILS at its deadline, and
//      a failed nightly job raises its counter in the pre-opening check, which emails
//      somebody before the pharmacy opens.
//   3. THE READINGS ARE TRANSITIONS, NOT ASSERTIONS. Every one of the seven compares a
//      monotonic counter against wall time, or requires a state change observed across two
//      separate readings. None is a success flag an executor sets.
//   4. THE DISRUPTIVE VERBS CANNOT LOOP ON A MISSING PROOF. vm.shutdown, vm.reboot and
//      counter.reboot are max_attempts 1 with retry_ok false, so "never confirmed" ends the
//      job rather than re-offering it.
//
// Per verb, `self_attested_acceptable_because` says whether that is enough for THAT verb.
// For vm.shutdown it says plainly that it is not — the confirmation there is an audit
// statement, not a control — and `confirm_independent_would_be` on every row is the
// buildable specification for taking the flag off. Nothing in this file claims a proof it
// does not have.
const SELF_ATTESTATION = Object.freeze({
  // The one-line answer for a UI, an audit export or a reviewer who reads no further.
  summary:
    'every verb in this table is confirmed by a reading its own executor authored. The '
    + 'hours gate, the attempts cap and the failure-towards-a-person direction are what make '
    + 'that safe — not the confirmation.',
  independence_test:
    'could the machine that executed the job produce this reading without the world having '
    + 'changed? If yes, it is self-attested. A different table is not a different observer.',
});

// ── verbs that are DEFINED but REFUSED ───────────────────────────────────────
// A verb with no confirming reading is not admitted. Keeping the refusal here, named, with
// the reading that would admit it, is what stops it being quietly added later with a
// "returned 0" for proof.
const UNADMITTED_VERBS = {
  'vm.session-logoff': {
    executor: 'proxmox-node',
    disruptive: true,
    would_do: 'sign the Windows session out from inside the guest, via the guest agent',
    refused_because:
      'nothing in this platform independently reads whether a Windows interactive session '
      + 'exists. proxmox_vms reports status, uptime, onboot, agent_ok and guest IPs — none of '
      + 'which change when a user signs out — and the Pi only reports whether its own RDP '
      + 'client is running, which is a reading of the Pi, not of the session.',
    would_be_admitted_by:
      'the Proxmox collector reporting a per-VM interactive-session count from '
      + 'agent/get-users (or an equivalent guest-agent read), so a logoff is proven by the '
      + 'count reaching zero in a reading taken AFTER the job was applied. Until that exists, '
      + 'the nightly restart signs out at the RDP layer with counter.session-restart.',
  },
};

// ── validation ───────────────────────────────────────────────────────────────

// Is this a verb at all? Exact match only, and the refusal names the admitted set — the same
// shape counterAction uses for PI_ACTIONS.
function isVerb(name) {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(VERBS, name);
}

function getVerb(name) {
  return isVerb(name) ? VERBS[name] : null;
}

// The ONE argument validator. Takes the verb name and an arbitrary object straight off the
// wire; returns { ok:true, value } holding only whitelisted, correctly typed, in-range keys,
// or { ok:false, error } naming the offending one.
//
// Keys marked `resolved` are ACCEPTED AND DISCARDED rather than refused: the caller sends a
// vmid because that is what it picked in the UI, and the server then resolves the real one
// from the rows it holds and overwrites it. Refusing the key would make every caller
// construct a half-empty object; silently keeping the caller's value would make the UI the
// authority on what an executor acts against, which is exactly what setCounterBootTarget
// exists to prevent.
function validateVerbArgs(name, input) {
  const spec = getVerb(name);
  if (!spec) {
    return { ok: false, error: `unknown verb "${name}" — allowed verbs are ${VERB_NAMES.join(', ')}` };
  }
  const src = input == null ? {} : input;
  if (typeof src !== 'object' || Array.isArray(src)) {
    return { ok: false, error: 'args must be a JSON object' };
  }
  const value = {};
  for (const key of Object.keys(src)) {
    // hasOwnProperty, never spec.args[key] — see counterSettings.js for why a truthiness
    // check is how a closed whitelist stops being closed.
    if (!Object.prototype.hasOwnProperty.call(spec.args, key)) {
      const allowed = Object.keys(spec.args);
      return {
        ok: false,
        error: allowed.length
          ? `"${name}" does not take an argument called "${key}" — it takes ${allowed.join(', ')}`
          : `"${name}" takes no arguments`,
      };
    }
    const argSpec = spec.args[key];
    const v = src[key];
    // Checked AS A NUMBER and never parsed out of a string: "1" from a <select> is a UI bug,
    // and coercing it hides the one class of bug this whitelist exists to catch.
    // Number.isInteger also rejects NaN, Infinity and 1.5.
    if (typeof v !== 'number' || !Number.isInteger(v)) {
      return { ok: false, error: `"${key}" must be a whole number sent as a JSON number, not a string` };
    }
    if (argSpec.type === 'enum') {
      if (!argSpec.values.includes(v)) {
        return { ok: false, error: `"${key}" must be one of ${argSpec.values.join(', ')}` };
      }
    } else if (v < argSpec.min || v > argSpec.max) {
      return { ok: false, error: `"${key}" must be an integer between ${argSpec.min} and ${argSpec.max}` };
    }
    if (argSpec.resolved) continue;   // accepted, then discarded — the server resolves it
    value[key] = v;
  }
  for (const key of Object.keys(spec.args)) {
    if (spec.args[key].resolved) continue;
    if (value[key] === undefined) return { ok: false, error: `"${name}" requires "${key}"` };
  }
  return { ok: true, value };
}

// ── intended state: the field table ──────────────────────────────────────────
// What Watchman may hold an intention ABOUT. Closed, like everything else here: an unknown
// field is an error rather than a silently stored row nothing will ever reconcile.
//
//   subject   which kind of row the intent hangs off.
//   want      the value spec, reusing ARG_SPECS so the intent and the verb that satisfies it
//             cannot disagree about what a legal value is.
//   via       'job'       the reconciler emits `verb` to close the gap.
//             'directive' the gap is already closed by a self-healing directive on the
//                         telemetry reply — the boot target is re-sent on EVERY tick
//                         precisely so a launcher edited by hand is corrected back. The
//                         reconciler must NOT also emit a job for these; a second mechanism
//                         pushing the same field is how a counter ends up flapping.
//   converges mirrors the verb's own flag, and it is the field that decides. A CONFIGURATION
//             property that is reversible, interrupts nothing and has a fresh independent
//             reading converges unattended. A LIFECYCLE property never does.
const INTENT_FIELDS = {
  'vm.onboot': {
    subject: 'vm',
    want: ARG_SPECS.onboot,
    via: 'job',
    verb: 'vm.set-onboot',
    converges: true,
    observed_from: 'proxmox_vms.onboot, written by the Proxmox collector',
  },
  'vm.running': {
    subject: 'vm',
    // Stored as 1|0 for the same reason onboot is: one vocabulary, one comparison.
    want: { type: 'enum', values: [0, 1] },
    via: 'job',
    // Two verbs, because the direction decides which. Named here so the reconciler never
    // has to infer an action from a value.
    verb_up: 'vm.start',
    verb_down: 'vm.shutdown',
    // NEVER. Power is a lifecycle property: a one-shot job with a time limit, raised by an
    // operator, not closed by a loop. A reconciler that powered VMs to match a stored wish
    // would fight the engineer who just stopped one.
    converges: false,
    observed_from: 'proxmox_vms.status, written by the Proxmox collector',
  },
  'counter.boot_vmid': {
    subject: 'counter',
    want: ARG_SPECS.vmid,
    // Already converged by the boot directive on the telemetry reply, which is re-sent every
    // tick and acknowledged from device_state.raw with no cooperation from the payload.
    // Recorded here so the UI shows one intent model for the whole site, NOT so a second
    // mechanism starts pushing it.
    //
    // ⚠️ AND THE STAGED value is NOT held here (D2). Deferring a boot target to the overnight
    // window needs to express "back to the site's PMR server", which is the ABSENCE of a
    // vmid — and there is no way to say that in a bounded-integer spec without a magic zero
    // inside a whitelist whose whole point is that it holds no magic values. It lives in
    // counters.boot_next_vmid / boot_next_pending instead. THIS row still means what it
    // always meant: the wanted value against the last OBSERVED one, which the reconciler
    // refreshes from counters.boot_applied_at.
    via: 'directive',
    converges: true,
    observed_from: "device_state.raw -> 'rdp' ->> 'configured_target', reported by the Pi agent",
  },
};

const INTENT_FIELD_NAMES = Object.keys(INTENT_FIELDS);

// Validate an intended-state write. Same contract as validateVerbArgs: a closed key set and
// a bounded value, refused rather than coerced.
function validateIntent(field, want) {
  if (!Object.prototype.hasOwnProperty.call(INTENT_FIELDS, field)) {
    return { ok: false, error: `unknown intent field "${field}" — allowed fields are ${INTENT_FIELD_NAMES.join(', ')}` };
  }
  const spec = INTENT_FIELDS[field].want;
  if (typeof want !== 'number' || !Number.isInteger(want)) {
    return { ok: false, error: `"${field}" must be a whole number sent as a JSON number, not a string` };
  }
  if (spec.type === 'enum') {
    if (!spec.values.includes(want)) {
      return { ok: false, error: `"${field}" must be one of ${spec.values.join(', ')}` };
    }
  } else if (want < spec.min || want > spec.max) {
    return { ok: false, error: `"${field}" must be an integer between ${spec.min} and ${spec.max}` };
  }
  return { ok: true, value: want };
}

module.exports = {
  VERBS,
  VERB_NAMES,
  PMR_JOB_AGENT_VERSION,
  PMR_JOB_COLLECTOR_VERSION,
  COUNTER_CHANNEL_AGENT_FLOOR,
  reportedAgentVersion,
  agentMeetsFloor,
  SELF_ATTESTATION,
  EXECUTORS,
  CONFIRM_KINDS,
  EXECUTOR_REPORTABLE_STATUSES,
  UNADMITTED_VERBS,
  INTENT_FIELDS,
  INTENT_FIELD_NAMES,
  isVerb,
  getVerb,
  validateVerbArgs,
  validateIntent,
};
