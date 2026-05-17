# Deployment Guide

End-to-end walkthrough for running the AI Risk Assessment Platform on
Kubernetes. The default profile is **import-only** — scanners run in your
CI/CD pipeline, the platform receives their results via HTTP and runs the
SP 800-30 assessment with warm caches.

## Prerequisites

- `kubectl` ≥ 1.27 against a target cluster
- Container registry write access (GitHub Container Registry, ECR, GCR, …)
- About 1 GiB free RAM and 1 vCPU per replica
- For Bedrock (AI) mode: an AWS account with Bedrock access granted to your Claude model in the target region
- For multi-replica deployments: persistent storage for Redis (1 GiB default)

---

## 1. Build and push the image

```bash
# From the repo root.
docker build -t ghcr.io/<owner>/ai-risk-platform:0.1.0 .
docker push   ghcr.io/<owner>/ai-risk-platform:0.1.0
```

Or, once you tag a release on the upstream repo, the included GitHub Actions
workflow (`.github/workflows/release.yml`) builds and publishes a multi-arch
image to `ghcr.io/<owner>/ai-risk-platform:<tag>` with cosign keyless signing.

Edit `deploy/kubernetes/30-deployment.yaml` and replace the `image:` field
with your reference.

---

## 2. Create the namespace and secrets

```bash
kubectl apply -f deploy/kubernetes/00-namespace.yaml

# Generate and apply the API key.
kubectl -n ai-risk-platform create secret generic ai-risk-platform-secrets \
  --from-literal=api-key=$(openssl rand -hex 32)
```

The API key gates every `/v1/*` route. Distribute it to CI/CD systems via
their own secret stores (GitHub Actions secrets, Vault, etc.) — never check it
into the repo.

---

## 3. Define your product(s)

Copy the example ConfigMap and edit it to describe **your** system:

```bash
cp deploy/kubernetes/11-configmap-products.example.yaml \
   deploy/kubernetes/11-configmap-products.yaml
# Edit data.product-manifest.yaml and data.risk-profile.yaml.
kubectl apply -f deploy/kubernetes/11-configmap-products.yaml
```

The Deployment mounts this ConfigMap at
`/etc/orchestrator/products/<name>/`. To add a second product, create a
second ConfigMap and add another `volumes:` + `volumeMounts:` entry in the
Deployment with `mountPath: /etc/orchestrator/products/<name2>`.

---

## 4. Apply the rest

```bash
kubectl apply -k deploy/kubernetes/
```

Watch the rollout:

```bash
kubectl -n ai-risk-platform get pods -w
```

You should see:
- 1 × `redis-0` (StatefulSet)
- 2 × `ai-risk-platform-…` (Deployment)

---

## 5. Verify

Port-forward and probe:

```bash
kubectl -n ai-risk-platform port-forward svc/ai-risk-platform 8080:80 &
KEY=$(kubectl -n ai-risk-platform get secret ai-risk-platform-secrets \
  -o jsonpath='{.data.api-key}' | base64 -d)

curl -sf http://127.0.0.1:8080/readyz
curl -sf -H "X-API-Key: $KEY" http://127.0.0.1:8080/v1/products
```

`/v1/products` should list whichever products you mounted.

---

## 6. Onboard a new product without redeploying

```bash
# 1. Edit / create the ConfigMap with the new product's manifest + profile.
kubectl -n ai-risk-platform apply -f deploy/kubernetes/11-configmap-products.yaml

# 2. Add a volume + volumeMount in the Deployment for that product, then:
kubectl -n ai-risk-platform rollout restart deployment/ai-risk-platform

# 3. Or, for in-place config edits to an already-mounted product, just reload:
curl -X POST -H "X-API-Key: $KEY" http://127.0.0.1:8080/v1/admin/reload
```

ConfigMap updates take ~60s to surface inside the pod (kubelet sync).
`/v1/admin/reload` re-reads from disk on every replica that handles the call.
In a multi-replica setup, hit the Service repeatedly (or call each pod) to
ensure all replicas see the new state.

---

## 7. Enable AI mode (Bedrock)

The default profile uses the static (deterministic) assessor. To switch to
per-finding Claude analysis:

1. **Request model access** in the AWS Bedrock console for the region you're
   deploying to. Without this, `BEDROCK_MODEL_ID` will succeed at import but
   fail at first invocation.
2. **Grant the pod IAM permissions** to call Bedrock.

### EKS (IRSA)

```bash
# Create an IAM role with bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream.
eksctl create iamserviceaccount \
  --name ai-risk-platform \
  --namespace ai-risk-platform \
  --cluster <your-cluster> \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonBedrockReadOnly \
  --approve --override-existing-serviceaccounts
```

Then uncomment the `eks.amazonaws.com/role-arn` annotation in
`20-serviceaccount.yaml`.

### GKE (Workload Identity)

Annotate the ServiceAccount with
`iam.gke.io/gcp-service-account: <gsa>@<project>.iam.gserviceaccount.com`,
then `gcloud iam service-accounts add-iam-policy-binding` the workload
identity user.

### Then in the Deployment

Uncomment `BEDROCK_MODEL_ID` and `AWS_DEFAULT_REGION` env vars in
`30-deployment.yaml`. The server logs `[serve] ... mode=bedrock` on startup
when the client initializes successfully.

When in Bedrock mode, the API rejects synchronous requests — clients must
send `async_mode: true` and poll `/v1/jobs/{id}`.

---

## 8. Scale up

```bash
kubectl -n ai-risk-platform scale deployment/ai-risk-platform --replicas=4
```

Cross-replica job sharing is automatic via Redis. The HPA in `50-hpa.yaml`
scales on CPU; for AI workloads scale on queue depth instead (use KEDA
against the `orchestrator:queue:assess` list length).

---

## 9. Network exposure

Pod-internal usage (other workloads in the same cluster call the platform):
the included `ClusterIP` Service is enough.

External access: use `deploy/kubernetes/60-ingress.example.yaml` as a
starting point. **TLS terminates at the Ingress** — the pod speaks plain
HTTP. Match your Ingress's `proxy-body-size` (or equivalent) to the server's
`--max-body-mb` (default 16 MiB).

---

## 10. Production-grade Redis

The bundled `40-redis.yaml` is a single-node StatefulSet — appropriate for
dev and small prod. For HA:

- **AWS**: swap for ElastiCache (Redis cluster mode disabled, AUTH on), point
  `--redis-url` at the primary endpoint.
- **GCP**: Memorystore for Redis.
- **Self-managed**: Bitnami's Redis Helm chart with Sentinel.

Delete `40-redis.yaml` from the kustomization and pass your real Redis URL via
the Deployment's `--redis-url` arg (or `ORCHESTRATOR_REDIS_URL` env).

---

## 11. Observability

Currently the platform logs structured access lines to stdout:

```
rid=<request-id> method=POST path=/v1/products/payment-api/assess status=202 elapsed_ms=12.3
```

Pipe `kubectl logs` into your aggregator (Loki, Datadog, ELK). Prometheus
metrics and OpenTelemetry tracing are not yet built in.

---

## 12. Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| `/readyz` returns `loading` | ServerState hasn't finished `load()` — usually transient on first boot. |
| `401 invalid or missing X-API-Key` | Caller didn't send the header, or the secret was rotated and not all replicas restarted. |
| `400 server is in bedrock (AI) mode; set async_mode=true` | You're using sync mode but the server picked up `BEDROCK_MODEL_ID`. Either unset the env or switch the caller. |
| `403 target_path is not within any configured scan root` | `scan-assess` requires `--scan-roots` to be configured. Default deployment ships scan-mode **disabled**. |
| Jobs stuck `pending` | Workers can't reach Redis, or the queue is at capacity. Check `kubectl logs` for `worker brpoplpush failed`. |
| Jobs ending in `failed` with `error_class: MaxRetriesExceeded` | A replica kept crashing on the same job; the janitor reclaimed it `--janitor-max-attempts` times and gave up. Inspect logs for the underlying error_id. |

---

## 13. Uninstall

```bash
kubectl delete -k deploy/kubernetes/
kubectl delete pvc -n ai-risk-platform -l app.kubernetes.io/name=redis  # if you want to wipe Redis data
kubectl delete namespace ai-risk-platform
```
