import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import type {
  PortalCredentialProvider,
  PortalCredentialStage,
  PortalServiceCredential,
} from "./types.js";

const DEFAULT_REFRESH_MS = 60_000;

function parseSecret(
  raw: string | undefined,
  expectedApp: string,
  stage: PortalCredentialStage
): PortalServiceCredential {
  let parsed: Partial<PortalServiceCredential>;
  try {
    parsed = JSON.parse(raw || "") as Partial<PortalServiceCredential>;
  } catch {
    throw new Error(`Portal credential ${stage} is not valid JSON.`);
  }
  if (
    parsed.schemaVersion !== 1 ||
    parsed.appKey !== expectedApp ||
    typeof parsed.credentialId !== "string" ||
    !/^[A-Za-z0-9_-]{8,128}$/.test(parsed.credentialId) ||
    typeof parsed.secret !== "string" ||
    !/^[A-Za-z0-9_-]{32,512}$/.test(parsed.secret)
  ) {
    throw new Error(`Portal credential ${stage} is invalid or bound to another app.`);
  }
  return {
    schemaVersion: 1,
    appKey: expectedApp,
    credentialId: parsed.credentialId,
    secret: parsed.secret,
    stage,
  };
}

export class AwsPortalCredentialProvider implements PortalCredentialProvider {
  private readonly client: SecretsManagerClient;
  private cached: PortalServiceCredential[] = [];
  private refreshAfter = 0;
  private inFlight?: Promise<PortalServiceCredential[]>;

  constructor(
    private readonly secretArn: string,
    private readonly appKey: string,
    region: string,
    private readonly refreshMs = DEFAULT_REFRESH_MS
  ) {
    this.client = new SecretsManagerClient({ region });
  }

  configured(): boolean {
    return !!this.secretArn;
  }

  async getCredentials(forceRefresh = false): Promise<PortalServiceCredential[]> {
    if (!forceRefresh && this.cached.length && Date.now() < this.refreshAfter) {
      return this.cached;
    }
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.load().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  close(): void {
    this.client.destroy();
  }

  private async load(): Promise<PortalServiceCredential[]> {
    try {
      const current = await this.client.send(
        new GetSecretValueCommand({
          SecretId: this.secretArn,
          VersionStage: "AWSCURRENT",
        })
      );
      const values = [
        parseSecret(current.SecretString, this.appKey, "AWSCURRENT"),
      ];
      try {
        const pending = await this.client.send(
          new GetSecretValueCommand({
            SecretId: this.secretArn,
            VersionStage: "AWSPENDING",
          })
        );
        values.unshift(parseSecret(pending.SecretString, this.appKey, "AWSPENDING"));
      } catch (error) {
        if (!isMissingPendingStage(error)) throw error;
      }
      this.cached = values;
      this.refreshAfter = Date.now() + this.refreshMs;
      return values;
    } catch (error) {
      // A temporary Secrets Manager outage must not take a previously loaded
      // connector offline. Portal still validates the stale credential and will
      // reject it after revocation, so this remains fail-closed.
      if (this.cached.length) return this.cached;
      throw error;
    }
  }
}

function isMissingPendingStage(error: unknown): boolean {
  const named = error as { name?: string; message?: string };
  if (named.name === "ResourceNotFoundException") return true;
  if (named.name !== "InvalidRequestException") return false;
  return /AWSPENDING|version stage|staging label/i.test(named.message || "");
}

export class StaticPortalCredentialProvider implements PortalCredentialProvider {
  constructor(private readonly credentials: PortalServiceCredential[]) {}
  configured(): boolean {
    return this.credentials.length > 0;
  }
  async getCredentials(): Promise<PortalServiceCredential[]> {
    return this.credentials.map((credential) => ({ ...credential }));
  }
}

export function defaultCredentialProvider(
  appKey: string,
  injected: PortalCredentialProvider | undefined,
  secretArn: string,
  region: string,
  refreshMs: number
): PortalCredentialProvider | undefined {
  if (injected) return injected;
  if (secretArn) {
    if (!region) throw new Error("AWS_REGION is required for the Portal credential secret.");
    return new AwsPortalCredentialProvider(secretArn, appKey, region, refreshMs);
  }
  const local = (process.env.PORTAL_APP_CREDENTIAL || "").trim();
  if (local && process.env.NODE_ENV !== "production" && !process.env.RENDER) {
    return new StaticPortalCredentialProvider([
      parseSecret(local, appKey, "AWSCURRENT"),
    ]);
  }
  return undefined;
}
