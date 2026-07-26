import assert from "node:assert/strict";
import { test } from "node:test";
import { AwsPortalCredentialProvider } from "../dist/index.js";

const CURRENT = {
  schemaVersion: 1,
  appKey: "example-app",
  credentialId: "current-credential",
  secret: "currentsecretcurrentsecretcurrentsecret123",
};

function secret(overrides = {}) {
  return JSON.stringify({ ...CURRENT, ...overrides });
}

function missingPending() {
  const error = new Error("Secrets Manager can't find AWSPENDING");
  error.name = "ResourceNotFoundException";
  return error;
}

function fakeClient(send) {
  return {
    send,
    destroy() {},
  };
}

test("AWS credentials are parsed, app-bound, and tolerate a missing pending stage", async () => {
  const calls = [];
  const abortController = new AbortController();
  const client = fakeClient(async (command, options) => {
    calls.push({
      stage: command.input.VersionStage,
      signal: options?.abortSignal,
    });
    if (command.input.VersionStage === "AWSCURRENT") {
      return { SecretString: secret() };
    }
    throw missingPending();
  });
  const provider = new AwsPortalCredentialProvider(
    "arn:aws:secretsmanager:ca-central-1:123456789012:secret:example",
    "example-app",
    "ca-central-1",
    60_000,
    client
  );

  const credentials = await provider.getCredentials(false, abortController.signal);
  assert.deepEqual(credentials, [{ ...CURRENT, stage: "AWSCURRENT" }]);
  assert.deepEqual(
    calls.map((call) => call.stage),
    ["AWSCURRENT", "AWSPENDING"]
  );
  assert.ok(calls.every((call) => call.signal instanceof AbortSignal));
  assert.ok(calls.every((call) => call.signal !== abortController.signal));
  assert.equal(new Set(calls.map((call) => call.signal)).size, 1);
  provider.close();
});

test("AWS credentials reject malformed values and another app's binding", async () => {
  for (const currentValue of [
    "{not-json",
    secret({ appKey: "another-app" }),
    secret({ credentialId: "short" }),
    secret({ secret: "short" }),
  ]) {
    const provider = new AwsPortalCredentialProvider(
      "arn:aws:secretsmanager:ca-central-1:123456789012:secret:example",
      "example-app",
      "ca-central-1",
      60_000,
      fakeClient(async () => ({ SecretString: currentValue }))
    );
    await assert.rejects(
      () => provider.getCredentials(),
      /not valid JSON|invalid or bound to another app/
    );
    provider.close();
  }
});

test("a refresh failure returns only a previously loaded stale cache", async () => {
  let currentLoads = 0;
  const provider = new AwsPortalCredentialProvider(
    "arn:aws:secretsmanager:ca-central-1:123456789012:secret:example",
    "example-app",
    "ca-central-1",
    0,
    fakeClient(async (command) => {
      if (command.input.VersionStage === "AWSPENDING") throw missingPending();
      currentLoads += 1;
      if (currentLoads > 1) throw new Error("Secrets Manager unavailable");
      return { SecretString: secret() };
    })
  );

  const loaded = await provider.getCredentials();
  const stale = await provider.getCredentials(true);
  assert.deepEqual(stale, loaded);
  assert.equal(currentLoads, 2);
  provider.close();
});

test("concurrent cold-cache requests coalesce into one Secrets Manager load", async () => {
  let releaseCurrent;
  const currentResponse = new Promise((resolve) => {
    releaseCurrent = resolve;
  });
  let currentLoads = 0;
  const provider = new AwsPortalCredentialProvider(
    "arn:aws:secretsmanager:ca-central-1:123456789012:secret:example",
    "example-app",
    "ca-central-1",
    60_000,
    fakeClient(async (command) => {
      if (command.input.VersionStage === "AWSPENDING") throw missingPending();
      currentLoads += 1;
      return currentResponse;
    })
  );

  const first = provider.getCredentials();
  const second = provider.getCredentials();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(currentLoads, 1);
  releaseCurrent({ SecretString: secret() });
  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.deepEqual(firstResult, secondResult);
  assert.equal(currentLoads, 1);
  await provider.getCredentials(true);
  assert.equal(currentLoads, 2, "completed in-flight load was not released");
  provider.close();
});

test("one caller's deadline cannot cancel another coalesced AWS waiter", async () => {
  let releaseCurrent;
  const currentResponse = new Promise((resolve) => {
    releaseCurrent = resolve;
  });
  let sharedSignal;
  const provider = new AwsPortalCredentialProvider(
    "arn:aws:secretsmanager:ca-central-1:123456789012:secret:example",
    "example-app",
    "ca-central-1",
    60_000,
    fakeClient(async (command, options) => {
      sharedSignal = options?.abortSignal;
      if (command.input.VersionStage === "AWSPENDING") throw missingPending();
      return currentResponse;
    })
  );
  const firstController = new AbortController();
  const secondController = new AbortController();
  const first = provider.getCredentials(false, firstController.signal);
  const second = provider.getCredentials(false, secondController.signal);
  await new Promise((resolve) => setImmediate(resolve));

  firstController.abort(new DOMException("first deadline", "TimeoutError"));
  await assert.rejects(first, (error) => error?.name === "TimeoutError");
  assert.equal(secondController.signal.aborted, false);
  assert.equal(sharedSignal.aborted, false);

  releaseCurrent({ SecretString: secret() });
  assert.deepEqual(await second, [{ ...CURRENT, stage: "AWSCURRENT" }]);
  provider.close();
});

test("an abort reaches Secrets Manager and never returns stale cache", async () => {
  const seenSignals = [];
  let currentLoads = 0;
  const client = fakeClient(async (command, options) => {
    seenSignals.push(options?.abortSignal);
    if (command.input.VersionStage === "AWSCURRENT") {
      currentLoads += 1;
      if (currentLoads === 1) return { SecretString: secret() };
    } else if (currentLoads === 1) {
      throw missingPending();
    }
    return new Promise((_, reject) => {
      const signal = options?.abortSignal;
      signal.addEventListener(
        "abort",
        () => reject(signal.reason),
        { once: true }
      );
    });
  });
  const provider = new AwsPortalCredentialProvider(
    "arn:aws:secretsmanager:ca-central-1:123456789012:secret:example",
    "example-app",
    "ca-central-1",
    0,
    client
  );
  await provider.getCredentials();

  const controller = new AbortController();
  const refresh = provider.getCredentials(true, controller.signal);
  controller.abort(new DOMException("test deadline", "TimeoutError"));
  await assert.rejects(refresh, (error) => error?.name === "TimeoutError");
  assert.ok(seenSignals.some((signal) => signal instanceof AbortSignal && signal.aborted));
  assert.ok(seenSignals.every((signal) => signal !== controller.signal));
  provider.close();
});
