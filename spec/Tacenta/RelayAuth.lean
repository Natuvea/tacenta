/-!
# Relay per-device authorization

The relay routes a per-device queue for each device, and an authenticated
connection is bound to one device. The authorization rule is that a connection
may only read (poll) and advance (ack) **its own** device's queue — never
another's. The delivery *semantics* of an ack (what advancing means, no replay,
no rewind) are proven separately in `Tacenta.Session` / `Tacenta.User`; this
file proves the *authorization* gate on top: who may act on which queue.

- `poll_own` / `poll_only_own` — a connection reads its own queue and no other.
- `ack_own_advances` — a connection may advance its own queue.
- `ack_only_own` — a connection cannot advance another device's queue.
- `ack_frames_others` — advancing one's own queue leaves every other device's
  queue untouched.

The queue advance is abstract (`advance : Queue → Queue`); what is proven is that
it is applied only to the authenticated device's own queue.
-/

namespace Tacenta.RelayAuth

variable {Device Queue : Type} [DecidableEq Device]

/-- The relay: a per-device queue. -/
abbrev Relay (Device Queue : Type) := Device → Queue

/-- Poll `target`'s queue as the connection authenticated for `authed` — allowed
only for the connection's own device. -/
def poll (r : Relay Device Queue) (authed target : Device) : Option Queue :=
  if target = authed then some (r target) else none

/-- Advance `target`'s queue as `authed` — a no-op unless `target` is the
connection's own device, in which case only that device's queue advances. -/
def ack (advance : Queue → Queue) (r : Relay Device Queue) (authed target : Device) :
    Relay Device Queue :=
  if target = authed then (fun d => if d = target then advance (r d) else r d) else r

/-- A connection reads its own device's queue. -/
theorem poll_own (r : Relay Device Queue) (authed : Device) :
    poll r authed authed = some (r authed) := by
  simp [poll]

/-- A connection cannot read another device's queue. -/
theorem poll_only_own (r : Relay Device Queue) (authed target : Device) (h : target ≠ authed) :
    poll r authed target = none := by
  simp [poll, h]

/-- A connection advances its own device's queue. -/
theorem ack_own_advances (advance : Queue → Queue) (r : Relay Device Queue) (authed : Device) :
    ack advance r authed authed authed = advance (r authed) := by
  simp [ack]

/-- A connection cannot advance another device's queue — the relay is unchanged. -/
theorem ack_only_own (advance : Queue → Queue) (r : Relay Device Queue) (authed target : Device)
    (h : target ≠ authed) :
    ack advance r authed target = r := by
  simp [ack, h]

/-- Advancing one's own queue leaves every other device's queue untouched. -/
theorem ack_frames_others (advance : Queue → Queue) (r : Relay Device Queue)
    (authed other : Device) (h : other ≠ authed) :
    ack advance r authed authed other = r other := by
  simp [ack, h]

end Tacenta.RelayAuth
