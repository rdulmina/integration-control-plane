// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

import icp_server.auth;
import icp_server.storage;
import icp_server.types;

import ballerina/http;
import ballerina/log;

// ── Workflow management proxy ────────────────────────────────────────────────
// Forwards frontend calls to the per-runtime workflow management REST service
// (base path `/workflow` on the runtime side). The reachable base URL is the
// `callbackUrl` reported in the heartbeat and stored on the `runtimes` row.
//
// Frontend → GET/POST https://<icp>/icp/workflow/{componentId}/{environmentId}/<wf-path>
//          → forwarded to <callbackUrl>/workflow/<wf-path>
//
// The proxy injects `x-user-id` and `x-user-roles` (the caller's ICP permission
// scopes, plus a synthetic `admin` role for super-admins) so the workflow
// service can do its own human-task authorization. It also authenticates to the
// runtime's management API with `X-API-Key: <keyId>.<keyMaterial>` — the same org
// secret the runtime registered with (configured as `apiKeyValue` in the runtime's
// `[ballerina.workflow.management]` section).

// Certificate validation for https callbackUrls is on by default. Set to true only to
// deliberately accept self-signed certs (K8s-internal / dev without a trusted chain).
configurable boolean workflowProxyAllowInsecureTLS = false;

// Request timeout (seconds) for calls to the runtime workflow service.
configurable decimal workflowProxyTimeout = 30;

const int WORKFLOW_CLIENT_CACHE_MAX_SIZE = 100;
isolated map<http:Client> workflowClientCache = {};

// Evicts cached clients whose callbackUrl no longer belongs to a RUNNING runtime.
isolated function pruneWorkflowClientCache() {
    string[]|error liveUrls = storage:getRunningWorkflowCallbackUrls();
    if liveUrls is error {
        log:printWarn("Workflow client cache prune skipped — failed to look up running runtimes",
                'error = liveUrls);
        return;
    }
    map<()> liveSetMut = {};
    foreach string url in liveUrls {
        liveSetMut[url] = ();
    }
    final readonly & map<()> liveSet = liveSetMut.cloneReadOnly();
    lock {
        foreach string cachedUrl in workflowClientCache.keys() {
            if !liveSet.hasKey(cachedUrl) {
                _ = workflowClientCache.remove(cachedUrl);
            }
        }
    }
}

isolated function getWorkflowClient(string baseUrl) returns http:Client|error {
    lock {
        if workflowClientCache.hasKey(baseUrl) {
            return workflowClientCache.get(baseUrl);
        }
    }
    http:ClientConfiguration cfg = {timeout: workflowProxyTimeout};
    if baseUrl.startsWith("https") && workflowProxyAllowInsecureTLS {
        cfg.secureSocket = {enable: false};
    }
    if !baseUrl.startsWith("https") {
        // Plain-http callback URLs send the runtime's management API key unencrypted.
        // Tolerated for local/dev runtimes; use an https callbackUrl in production.
        log:printWarn("Workflow runtime callback URL uses plain http; the management API key "
                + "will be sent unencrypted. Use an https callbackUrl in production.", callbackUrl = baseUrl);
    }
    http:Client newClient = check new (baseUrl, cfg);
    lock {
        // Re-check in case another worker created it meanwhile.
        if workflowClientCache.hasKey(baseUrl) {
            return workflowClientCache.get(baseUrl);
        }
        if workflowClientCache.length() >= WORKFLOW_CLIENT_CACHE_MAX_SIZE {
            workflowClientCache.removeAll();
        }
        workflowClientCache[baseUrl] = newClient;
    }
    return newClient;
}

// Reconstructs the runtime's workflow management API key (`<keyId>.<keyMaterial>`) from the
// org secret the runtime registered with. Returns () when the runtime has no recorded key id
// or the secret can't be resolved — the request is then sent without an API key (only valid
// against runtimes that don't enable API-key auth).
isolated function resolveWorkflowApiKey(string? keyId) returns string? {
    if keyId is () {
        return ();
    }
    types:OrgSecret|error orgSecret = storage:lookupOrgSecretByKeyId(keyId);
    if orgSecret is error {
        log:printWarn(string `Workflow proxy: failed to resolve API key for keyId=${keyId}`, 'error = orgSecret);
        return ();
    }
    return orgSecret.keyId + "." + orgSecret.keyMaterial;
}

// Fetches workflow definitions live from the runtime's GET /workflow/definitions API for the
// given component+environment and maps them to the Workflow artifact shape used by the frontend.
// Returns [] when no running runtime advertises a workflow callback URL, or when the runtime's
// workflow management API is not reachable (see below). Used by the GraphQL
// `workflowsByEnvironmentAndComponent` resolver (definitions are no longer carried in heartbeats).
isolated function fetchWorkflowDefinitions(string componentId, string environmentId) returns types:Workflow[]|error {
    types:WorkflowTarget?|error target = storage:getRuntimeWorkflowTarget(componentId, environmentId);
    if target is error {
        return target;
    }
    if target is () {
        return [];
    }

    map<string|string[]> headers = {};
    string? apiKey = resolveWorkflowApiKey(target.keyId);
    if apiKey is string {
        headers["X-API-Key"] = apiKey;
    }
    http:Client wfClient = check getWorkflowClient(target.callbackUrl);
    // The runtime now always reports a callbackUrl, so its presence no longer indicates that workflow
    // management is enabled — reachability does. The management API listener only runs when the runtime
    // sets `[ballerina.workflow.management] enableManagementApi = true`; otherwise this call fails at the
    // connection level. Treat that as "no workflows" so the feature is hidden gracefully rather than
    // surfacing an error. (A reachable-but-erroring API still returns a non-200 error below.)
    http:Response|error resp = wfClient->get("/workflow/definitions", headers);
    if resp is error {
        log:printDebug("Workflow management API not reachable; treating component as having no workflows",
                componentId = componentId, environmentId = environmentId, callbackUrl = target.callbackUrl, 'error = resp);
        return [];
    }
    if resp.statusCode != 200 {
        // Keep the upstream payload out of the client-facing error; log it for diagnosis.
        json|error errBody = resp.getJsonPayload();
        log:printError("Workflow definitions request failed", statusCode = resp.statusCode,
                upstreamBody = errBody is json ? errBody.toString() : "");
        return error(string `Workflow definitions request failed (status ${resp.statusCode})`);
    }
    json payload = check resp.getJsonPayload();
    json definitionsJson = check payload.definitions;
    types:WorkflowDefinition[] defs = check definitionsJson.cloneWithType();

    // Definitions are shared across the component+environment's runtimes; attach them for the UI.
    types:Runtime[] runtimes = check storage:getRuntimes((), (), environmentId, (), componentId);
    types:ArtifactRuntimeInfo[] runtimeInfos = from var r in runtimes
        select {runtimeId: r.runtimeId, runtimeName: r?.runtimeName, status: r.status};

    types:Workflow[] result = [];
    foreach types:WorkflowDefinition d in defs {
        boolean active = d.isActive ?: false;
        result.push({
            name: d.workflowType,
            isActive: active,
            workerCount: d.workerCount ?: 0,
            inputSchema: d?.inputSchema,
            state: active ? types:ENABLED : types:DISABLED,
            runtimes: runtimeInfos
        });
    }
    return result;
}

// Escapes a role name for the comma-joined `x-user-roles` header (`,` → `%2C`).
// Role names are user-created, so a literal comma would otherwise let a role like
// `Foo,admin` inject the synthetic `admin` role when the runtime splits the header.
// Names without commas pass through unchanged, so runtime-side role matching is unaffected.
// The frontend reverses this for display (unescapeRoleName in workflow/helpers.ts).
isolated function escapeRoleName(string roleName) returns string {
    return re `,`.replaceAll(roleName, "%2C");
}

isolated function workflowErrorResponse(int statusCode, string message) returns http:Response {
    http:Response res = new;
    res.statusCode = statusCode;
    res.setJsonPayload({"error": {"message": message}});
    return res;
}

// Performs auth, runtime resolution, header injection and forwarding for one
// workflow management request; returns the response to relay to the caller.
function proxyWorkflowRequest(string componentId, string environmentId, string[] wfPath, http:Request req) returns http:Response {
    // 1. Identify the caller from the (already JWT-validated) Authorization header.
    string|http:HeaderNotFoundError authHeader = req.getHeader("Authorization");
    if authHeader is http:HeaderNotFoundError {
        return workflowErrorResponse(401, "Authorization header missing");
    }
    types:UserContextV2|error userContext = auth:extractUserContextV2(authHeader);
    if userContext is error {
        return workflowErrorResponse(401, "Invalid token: " + userContext.message());
    }

    // 2. Authorize with the dedicated workflow permissions (scoped to the integration).
    //    - human-tasks: browsing needs view_human_tasks; acting needs manage_human_tasks.
    //    - everything else (workflows lifecycle, definitions, retry-tasks): browsing needs
    //      view_workflows; any mutation needs manage_workflows.
    string|error projectId = storage:getProjectIdByComponentId(componentId);
    if projectId is error {
        return workflowErrorResponse(404, "Component not found: " + componentId);
    }
    types:AccessScope scope = {
        orgUuid: 1,
        projectUuid: projectId,
        integrationUuid: componentId,
        envUuid: environmentId
    };
    string method = req.method;
    string firstSeg = wfPath.length() > 0 ? wfPath[0] : "";
    string[] allowedPermissions;
    if firstSeg == "human-tasks" {
        allowedPermissions = method == http:GET
            ? [auth:PERMISSION_WORKFLOW_VIEW_HUMAN_TASKS, auth:PERMISSION_WORKFLOW_MANAGE_HUMAN_TASKS]
            : [auth:PERMISSION_WORKFLOW_MANAGE_HUMAN_TASKS];
    } else {
        allowedPermissions = method == http:GET
            ? [auth:PERMISSION_WORKFLOW_VIEW_WORKFLOWS, auth:PERMISSION_WORKFLOW_MANAGE_WORKFLOWS]
            : [auth:PERMISSION_WORKFLOW_MANAGE_WORKFLOWS];
    }
    boolean|error permitted = auth:hasAnyPermission(userContext.userId, allowedPermissions, scope);
    if permitted is error {
        return workflowErrorResponse(500, "Authorization check failed: " + permitted.message());
    }
    if !permitted {
        log:printWarn("Workflow proxy access denied", userId = userContext.userId, componentId = componentId, method = method);
        return workflowErrorResponse(403, "Access denied");
    }

    // 3. Resolve the runtime workflow service base URL.
    types:WorkflowTarget?|error target = storage:getRuntimeWorkflowTarget(componentId, environmentId);
    if target is error {
        return workflowErrorResponse(500, "Failed to resolve workflow runtime: " + target.message());
    }
    if target is () {
        return workflowErrorResponse(503, "No running workflow runtime with a callback URL for this environment");
    }

    // 4. Build the target path (preserve the original query string verbatim).
    string subPath = string:'join("/", ...wfPath);
    string rawPath = req.rawPath;
    int? qIdx = rawPath.indexOf("?");
    string query = qIdx is int ? rawPath.substring(qIdx) : "";
    string targetPath = "/workflow/" + subPath + query;

    // 5. Inject identity headers. Forward the caller's ICP role names (each escaped, see
    //    escapeRoleName) so the workflow service can match/authorize human tasks by role.
    //    Drop ICP's bearer token and
    //    authenticate to the runtime's management API with its API key instead.
    string[]|error roleNames = storage:getAllUserRoleNames(userContext.userId);
    if roleNames is error {
        return workflowErrorResponse(500, "Failed to resolve user roles: " + roleNames.message());
    }
    string roles = string:'join(",", ...roleNames.map(escapeRoleName));
    boolean|error superAdmin = auth:isSuperAdmin(userContext.userId);
    if superAdmin is boolean && superAdmin {
        roles = roles.length() > 0 ? roles + ",admin" : "admin";
    }
    req.setHeader("x-user-id", userContext.userId);
    req.setHeader("x-user-roles", roles);
    req.removeHeader("Authorization");
    string? apiKey = resolveWorkflowApiKey(target.keyId);
    if apiKey is string {
        req.setHeader("X-API-Key", apiKey);
    }

    // 6. Forward (method + body preserved) and relay the upstream response. A connection-level
    //    failure means the runtime's workflow management API isn't running (it starts only when the
    //    runtime sets `[ballerina.workflow.management] enableManagementApi = true`). The runtime now
    //    always reports a callbackUrl, so reachability — not its presence — tells us the feature is on.
    //    Surface that as 503 (same as "no workflow runtime"), which the frontend treats as the feature
    //    being unavailable, rather than 502 which reads as an upstream fault.
    http:Client|error wfClient = getWorkflowClient(target.callbackUrl);
    if wfClient is error {
        return workflowErrorResponse(503, "Workflow management is not available for this environment");
    }
    http:Response|error upstream = wfClient->forward(targetPath, req);
    if upstream is error {
        log:printDebug("Workflow management API not reachable; forward failed", targetPath = targetPath, 'error = upstream);
        return workflowErrorResponse(503, "Workflow management is not available for this environment");
    }
    return upstream;
}

@http:ServiceConfig {
    auth: [
        {
            jwtValidatorConfig: {
                issuer: frontendJwtIssuer,
                audience: frontendJwtAudience,
                signatureConfig: {
                    secret: resolvedFrontendJwtHMACSecret
                }
            }
        }
    ],
    cors: {
        allowOrigins: normalizedCorsAllowedOrigins,
        allowHeaders: ["Content-Type", "Authorization"]
    }
}
service /icp/workflow on httpListener {

    function init() {
        log:printInfo("Workflow management proxy started at " + serverHost + ":" + serverPort.toString());
    }

    // Catch-all forwarders. {componentId}/{environmentId} pin the target runtime;
    // the remaining segments + query are forwarded verbatim to <callbackUrl>/workflow/...
    // Explicit get/post accessors (not 'default) so CORS preflight OPTIONS is
    // auto-handled by the listener and not subjected to service auth. The workflow
    // management API only uses GET and POST.
    resource function get [string componentId]/[string environmentId]/[string... wfPath](http:Caller caller, http:Request req) returns error? {
        check caller->respond(proxyWorkflowRequest(componentId, environmentId, wfPath, req));
    }

    resource function post [string componentId]/[string environmentId]/[string... wfPath](http:Caller caller, http:Request req) returns error? {
        check caller->respond(proxyWorkflowRequest(componentId, environmentId, wfPath, req));
    }
}
