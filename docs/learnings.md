
[Vault Admin Setup]
    │
    ├─ Enable GCP secrets engine at “gcp/”
    │
    ├─ Configure base service account credentials (with IAM role “Service Account Token Creator” on target SA)
    │
    └─ Define impersonated account:
         • service_account_email = workload-sa@project
         • token_scopes = cloud-platform
         • ttl (e.g. 1h)

                │
                ▼

[App / Runtime Flow]
    │
    ├─ App authenticates to Vault (Auth method: AppRole / auth/GCP / etc.)
    │       → gets Vault token (auth.client_token)
    │
    ├─ App calls:
    │       POST /v1/gcp/impersonated-account/workload/token
    │       with Vault token in header
    │
    ├─ Vault uses the base SA + IAM to call Google IAM Credentials API behind the scenes, impersonating workload-sa
    │
    ├─ Vault returns:
    │       • access_token (Bearer token)
    │       • expires_at_seconds
    │       • token_ttl
    │
    └─ App uses that `access_token` to call GCP APIs

[Optional / Operational]
    ├─ When token expires (~1h), repeat call
    └─ Vault policies ensure security: restrict which paths/methods the AppRole can call


Awesome—let’s turn that outline into a copy-pasteable playbook with exact commands, IAM, Vault policy, and a small Java client for runtime.

Flow 1 — Vault Admin Setup (one-time)

1) GCP IAM prerequisites
PROJECT_ID=my-project
BASE_SA=vault-base@${PROJECT_ID}.iam.gserviceaccount.com   # used by Vault under the hood
TARGET_SA=workload-sa@${PROJECT_ID}.iam.gserviceaccount.com # the identity your apps will “become”

# Grant the base SA permission to mint tokens for the target SA
gcloud iam service-accounts add-iam-policy-binding ${TARGET_SA} \
  --member="serviceAccount:${BASE_SA}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project=${PROJECT_ID}
The target SA should hold the real permissions (e.g., Storage Admin, BigQuery JobUser, DocAI User). Keep the base SA minimal—only Token Creator on the target SA.

2) Enable the GCP secrets engine
vault secrets enable gcp
3) Configure Vault’s GCP backend with base credentials
•	If you’re bootstrapping with a key file (most common):
vault write gcp/config credentials=@base-sa.json
This stays server-side in Vault. Your apps never see it.

(Alt: you can configure the backend to use GCE/Workload Identity so no key file is needed, but skip that unless you’re running Vault on GCP.)

4) Define the 
impersonated account
 (your “workload” identity)
vault write gcp/impersonated-account/workload \
  service_account_email="${TARGET_SA}" \
  token_scopes="https://www.googleapis.com/auth/cloud-platform" \
  ttl="3600s"
5) Vault policy to allow apps to fetch tokens

Create gcp-workload.hcl:
# Allow fetching a short-lived OAuth2 token for the impersonated account "workload"
path "gcp/impersonated-account/workload/token" {
  capabilities = ["read", "update"]
}
Load it:
vault policy write gcp-workload gcp-workload.hcl
6) Bind your auth method to the policy (example: AppRole)
# create role with the policy
vault write auth/approle/role/myapp \
  token_policies="gcp-workload" \
  token_ttl=1h token_max_ttl=4h

# retrieve RoleID & SecretID for your app (give to app securely)
vault read auth/approle/role/myapp/role-id
vault write -f auth/approle/role/myapp/secret-id
✅ At this point, Vault is ready. The only thing your app needs is RoleID + SecretID (or whichever auth you use) and the Vault address.
 
Flow 2 — App / Runtime (repeat every ~hour)

1) App authenticates to Vault
VAULT_ADDR=https://vault.example.com
ROLE_ID=...
SECRET_ID=...

LOGIN_JSON=$(curl -s -X POST "$VAULT_ADDR/v1/auth/approle/login" \
  -d "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}")

VAULT_TOKEN=$(echo "$LOGIN_JSON" | jq -r '.auth.client_token')
2) Ask Vault for a short-lived 
GCP OAuth2 token
TOKEN_JSON=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/gcp/impersonated-account/workload/token")

ACCESS_TOKEN=$(echo "$TOKEN_JSON" | jq -r '.data.token')
EXPIRES_AT=$(echo "$TOKEN_JSON" | jq -r '.data.expires_at_seconds')
3) Use it with GCP APIs

HTTP example:
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" \
     https://storage.googleapis.com/storage/v1/b
Java helper (minimal, no external HTTP libs)
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.OAuth2Credentials;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import java.io.IOException;
import java.net.http.*;
import java.net.URI;
import java.time.Instant;
import java.util.*;

// 1) AppRole login → Vault token
static String vaultLogin(String vaultAddr, String roleId, String secretId) throws Exception {
  var client = HttpClient.newHttpClient();
  var body = String.format("{\"role_id\":\"%s\",\"secret_id\":\"%s\"}", roleId, secretId);
  var req = HttpRequest.newBuilder(URI.create(vaultAddr + "/v1/auth/approle/login"))
      .header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(body)).build();
  var res = client.send(req, HttpResponse.BodyHandlers.ofString());
  var json = new org.json.JSONObject(res.body());
  return json.getJSONObject("auth").getString("client_token");
}

// 2) Fetch short-lived GCP token from Vault
static AccessToken gcpAccessTokenFromVault(String vaultAddr, String vaultToken) throws Exception {
  var client = HttpClient.newHttpClient();
  var req = HttpRequest.newBuilder(URI.create(vaultAddr + "/v1/gcp/impersonated-account/workload/token"))
      .header("X-Vault-Token", vaultToken)
      .POST(HttpRequest.BodyPublishers.noBody()).build();
  var res = client.send(req, HttpResponse.BodyHandlers.ofString());
  var data = new org.json.JSONObject(res.body()).getJSONObject("data");
  String token = data.getString("token");
  long expEpoch = data.getLong("expires_at_seconds");
  return new AccessToken(token, Date.from(Instant.ofEpochSecond(expEpoch)));
}

// 3) Use token with Google client libraries or raw HTTP
static void listBucketsWithHttp(AccessToken at) throws IOException {
  OAuth2Credentials creds = OAuth2Credentials.create(at);
  var transport = new NetHttpTransport();
  var factory = transport.createRequestFactory(new HttpCredentialsAdapter(creds));
  var url = new GenericUrl("https://storage.googleapis.com/storage/v1/b");
  var request = factory.buildGetRequest(url);
  HttpResponse response = request.execute();
  System.out.println(response.parseAsString());
}
Replace the endpoint with any GCP API you use (DocAI, BigQuery, etc.). On expiry, just repeat Flow 2.
 
Optional: Vault Agent (auto-fetch & template to file)

If you don’t want your app to talk to Vault directly, run Vault Agent sidecar:
# agent.hcl
exit_after_auth = false
pid_file = "./pidfile"
auto_auth {
  method "approle" {
    config = { role_id = "..." secret_id = "..." }
  }
  sink "file" { config = { path = "/tmp/vault.token" } }
}
template {
  source      = "/etc/vault/templates/gcp_token.ctmpl"
  destination = "/tmp/gcp_access_token"
}
gcp_token.ctmpl:
{{ with secret "gcp/impersonated-account/workload/token" -}}
{{ .Data.token }}
{{- end }}
Your app just reads /tmp/gcp_access_token and uses it as the Bearer token.
 
Security & Ops checklist (quick)
•	Least privilege: base SA only needs roles/iam.serviceAccountTokenCreator on the target SA.
•	Short TTLs: 1h is good. Let apps refresh.
•	Clock skew: ensure NTP; tokens are time-bound.
•	Scopes: start with cloud-platform, restrict if needed.
•	Policies: lock AppRole to only .../workload/token.
•	Rotation: rotate AppRole secret_id periodically.
•	Audit: enable Vault audit device; review who requested tokens.

If you share which GCP APIs you’ll call first (DocAI, BigQuery, GCS, etc.), I’ll drop in the exact Java client call using the same AccessToken.

