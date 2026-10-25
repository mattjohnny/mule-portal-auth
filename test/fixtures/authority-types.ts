import type { Context, PortalAuthConfig, AsyncPortalAuthConfig, PortalAppDirectory } from "../../dist/index.js";
import { createPortalAuth, createPortalAuthAsync } from "../../dist/index.js";

// Older consumers can still construct the previous scalar contract.
const legacy: Context = {
  email: "synthetic@example.invalid", name: "Synthetic", role: "manager",
  is_admin: false, status: "active", active: true,
  locations: [{ id: 1, key: "hamilton", name: "Hamilton" }], apps: ["hr"], ctx_version: 1,
};
const scalarRole: string = legacy.role;

// Both public entrypoints return the typed current directory.
async function consumers(syncConfig: PortalAuthConfig, asyncConfig: AsyncPortalAuthConfig) {
  for (const auth of [createPortalAuth(syncConfig), createPortalAuthAsync({ ...asyncConfig, authorityMode: "request" })]) {
    const directory: PortalAppDirectory = await auth.readAppDirectory({ include_non_mule: true });
    const isMule: boolean = directory.locations[0].is_mule;
    const roles: string[] = directory.people[0].roles;
    const permission: string | undefined = directory.people[0].permissions[0];
    void [isMule, roles, permission];
  }
}
void [scalarRole, consumers];
