// The conversation every check of the TypeScript head runs: two users sign
// up and in, find each other, message both ways, and one resumes from
// exported state and receives again. Shared by the end-to-end test (against
// a local server) and the conformance run (against hosted Tacenta), so the
// two exercise the same thing and drift together or not at all.

const suffix = () => Math.random().toString(16).slice(2, 10);

/**
 * Run the conversation on `tenant`, reporting each step through `log`.
 * Throws on the first mismatch. Returns the addresses involved.
 */
export async function conversation(tenant, log = () => {}) {
  const a = `conform-a-${suffix()}`;
  const b = `conform-b-${suffix()}`;
  const password = `p-${suffix()}-${suffix()}`;
  await tenant.signUp(a, password);
  await tenant.signUp(b, password);
  log(`signed up ${a} and ${b}`);

  const alice = await tenant.signIn(a, password);
  const bob = await tenant.signIn(b, password);
  log(`signed in as ${alice.address} and ${bob.address}`);

  const refused = await kindOf(() => tenant.signIn(a, `${password}-wrong`));
  expect(refused === "signInRefused", `a wrong password was refused as ${refused}`);
  log(`a wrong password was refused as ${refused}`);
  const taken = await kindOf(() => tenant.signUp(a, password));
  expect(taken === "usernameTaken", `a second sign-up was refused as ${taken}`);
  log(`a second sign-up was refused as ${taken}`);

  const toBob = await alice.find(b);
  expect(toBob === bob.address, `find(${b}) gave ${toBob}, expected ${bob.address}`);
  expect((await alice.find(`nobody-${suffix()}`)) === undefined, "find of a stranger was not undefined");
  log(`found ${b} at ${toBob}`);

  const tenantName = toBob.split("/")[0];
  const nobody = await kindOf(() => alice.send(`${tenantName}/nobody-${suffix()}/1`, "to no one"));
  expect(nobody === "notFound", `a send to an unregistered address was refused as ${nobody}`);
  log(`a send to an unregistered address was refused as ${nobody}`);

  await alice.send(toBob, "conformance: first contact");
  const inbox = await bob.receive();
  expectTexts(inbox, ["conformance: first contact"], `${b} received`);
  expect(inbox[0].from === alice.address, `from was ${inbox[0].from}`);
  log(`${b} received the first message from ${inbox[0].from}`);

  await bob.send(alice.address, new TextEncoder().encode("conformance: reply"));
  expectTexts(await alice.receive(), ["conformance: reply"], `${a} received`);
  log(`${a} received the reply`);

  // A receive left pending does not hold the client: a send goes through
  // meanwhile, and the pending receive gets the reply it provokes.
  const pending = alice.receive();
  await alice.send(toBob, "conformance: while receiving");
  expectTexts(await bob.receive(), ["conformance: while receiving"], `${b} received while ${a} was receiving`);
  await bob.send(alice.address, "conformance: to the pending receive");
  expectTexts(await pending, ["conformance: to the pending receive"], `the pending receive of ${a}`);
  log(`${a} sent while its own receive was pending, and that receive got the reply`);

  // The stream form: the same receive underneath, one message at a time.
  await bob.send(alice.address, "conformance: through the stream");
  const streamed = await alice.inbound().next();
  expectTexts(streamed.done ? [] : [streamed.value], ["conformance: through the stream"], `the inbound stream of ${a}`);
  log(`${a} took the next message from its inbound stream`);

  const state = await alice.exportState();
  const again = await tenant.signInWithState(a, password, state);
  const outcome = await again.restoreOutcome();
  expect(outcome === "resumed", `the restore outcome of ${a} was ${outcome}`);
  await bob.send(again.address, "conformance: after resume");
  expectTexts(await again.receive(), ["conformance: after resume"], `resumed ${a} received`);
  log(`${a} resumed from ${state.length} bytes of state and received again`);

  return { alice: alice.address, bob: bob.address };
}

/** The kind a call fails with, or "accepted" if it did not fail. */
async function kindOf(call) {
  try {
    await call();
    return "accepted";
  } catch (e) {
    return e && typeof e === "object" && "kind" in e ? e.kind : `an untyped error: ${e}`;
  }
}

function expect(ok, message) {
  if (!ok) throw new Error(message);
}

function expectTexts(messages, texts, what) {
  const got = messages.map((m) => m.text());
  expect(
    got.length === texts.length && got.every((t, i) => t === texts[i]),
    `${what} ${JSON.stringify(got)}, expected ${JSON.stringify(texts)}`,
  );
}
