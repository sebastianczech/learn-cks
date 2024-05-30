# Certified Kubernetes Security Specialist (CKS)

## Overview

Links:
* [Certification - Certified Kubernetes Security Specialist (CKS)](https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist/)
* [Open Source Curriculum for CNCF Certification Courses](https://github.com/cncf/curriculum)
* [Trivy - a comprehensive and versatile security scanner](https://github.com/aquasecurity/trivy)
* [Sysdig Documentation Hub](https://docs.sysdig.com/en/)
* [The Falco Project -Cloud Native Runtime Security](https://falco.org/docs/)
* [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)

## Tips

Links:
* [CKAD: 2021 tips, vimrc, bashrc and cheatsheet](https://dev.to/marcoieni/ckad-2021-tips-vimrc-bashrc-and-cheatsheet-hp3)

## Allowed access

* Kubernetes Documentation: 
  * https://kubernetes.io/docs/ and their subdomains
  * https://kubernetes.io/blog/ and their subdomains
* Tools:
  * Trivy documentation https://aquasecurity.github.io/trivy/
  * Falco documentation https://falco.org/docs/
  * etcd documentation https://etcd.io/docs/
* App Armor:
  * Documentation https://gitlab.com/apparmor/apparmor/-/wikis/Documentation

### Auto completion (`.bashrc`)

```
source <(kubectl completion bash)
alias k=kubectl
complete -F __start_kubectl k # autocomplete k
```

### Vi settings (`.vimrc`)

```
set nu # set numbers
set tabstop=2 shiftwidth=2 expandtab # use 2 spaces instead of tab
set ai # autoindent: when go to new line keep same indentation
```

### Multi node `kind` cluster

Links:
* [kind - Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/)
* [kind - multi-node install with Calico](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind)

Commands:
```bash
kind create cluster --config kind-multi-node.yaml
```

## Notes

### 1 - Cluster Setup

#### Network policies

Links:
* [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

Default deny all ingress traffic:
```yaml
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

Allow ingress traffic from CIDR, namespace and pod with correct label to port TCP/6379. Egress traffic is allowed from CIDR to port TPC/5978:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
```

#### CIS Benchmark

Links:
* [Aqua kube-bench](https://github.com/aquasecurity/kube-bench)
* [CIS Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

Jobs for control plane and workers:

```bash
k apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml
k apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-node.yaml

k get pods

k logs <JOB_FOR_MASTER>
k logs <JOB_FOR_NODE>
```

##### Examples of solution for problems detected by CIS Benchmark

###### Disable anonymous requests to the API server.

Links:
* [1.2.1 Ensure that the --anonymous-auth argument is set to false](https://www.tenable.com/audits/items/CIS_Kubernetes_v1.6.1_Level_1_Master.audit:ed6e2c11c6cdf4de68f7dda0f49fd8f7)
* [Set Kubelet Parameters Via A Configuration File](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/)
* [Configuring each kubelet in your cluster using kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/kubelet-integration/)

Define authorization in `/var/lib/kubelet/config.yaml`:
```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: 0.0.0.0
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
clusterDNS:
- 10.96.0.10
clusterDomain: cluster.local
cpuManagerReconcilePeriod: 10s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
healthzBindAddress: 127.0.0.1
healthzPort: 10248
kind: KubeletConfiguration
kubeletCgroups: /systemd/system.slice
kubeReserved:
  cpu: 200m
  memory: 250Mi
nodeStatusUpdateFrequency: 10s
resolvConf: /run/systemd/resolve/resolv.conf
rotateCertificates: true
runtimeRequestTimeout: 2m0s
```

Command:
```bash
sudo systemctl restart kubelet
```

Change in `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```
--anonymous-auth=false
```

###### Disable profiling

Links:
* [1.2.21 Ensure that the --profiling argument is set to false](https://www.tenable.com/audits/items/CIS_Kubernetes_v1.5.1_Level_1.audit:771c311a435fc7fe73f54b59ec6a3c43)

Change in `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```
--profiling=false
```

###### Do not always authorize all requests

Links:
* [1.2.7 Ensure that the --authorization-mode argument is not set to AlwaysAllow](https://www.tenable.com/audits/items/CIS_Kubernetes_v1.6.1_Level_1_Master.audit:26d0527252183cdd50ed8ddffc5241d9)
* [Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)

Change in `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```
--authorization-mode=RBAC
```

###### Enable client authentication on etcd service.

Links:
* [1.5.2 Ensure that the --client-cert-auth argument is set to true](https://www.tenable.com/audits/items/CIS_Kubernetes_v1.1.0_Level_1.audit:53322ecc4172b9c8acf61fbd62297490)
* [Role-based access control](https://etcd.io/docs/v3.4/op-guide/authentication/)

Change in `/etc/systemd/system/multi-user.target.wants/etcd.service`:
```
--client-cert-auth=true
```

#### Turn off profiling

Links:
* [kube-apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
* [kube-controller-manager](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
* [kube-scheduler](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)

Files:
- `/etc/kubernetes/manifests/kube-apiserver.yaml`
- `/etc/kubernetes/manifests/kube-controller-manager.yaml`
- `/etc/kubernetes/manifests/kube-scheduler.yaml`

Changes:
```yaml
...
spec:
  containers:
  - command:
...
    - --profiling=false
...
```

Commands:
```bash
sudo systemctl restart kubelet
```

#### Kubelet authorization to use webhook mode

Links:
* [Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
* [Webhook Mode](https://kubernetes.io/docs/reference/access-authn-authz/webhook/)

Changes in `/var/lib/kubelet/config.yaml`:
```yaml
authorization:
  mode: Webhook
```

Commands:
```bash
sudo systemctl restart kubelet
```

#### Use Ingress to implement TLS termination for the Service

Links:
* [Certificates and Certificate Signing Requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)
* [Ingress with TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
* [netshoot: a Docker + Kubernetes network trouble-shooting swiss-army container](https://github.com/nicolaka/netshoot)

Secret with certificate:
```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: seba-tls-certs
  namespace: seba
data:
  tls.crt: |
    <base64-encoded cert data from file seba.crt>
  tls.key: |
    <base64-encoded key data from file seba.key>
```

Ingress with TLS:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: seba-tls-ingress
  namespace: seba
spec:
  tls:
  - hosts:
      - seba.svc
    secretName: seba-tls-certs
  rules:
  - host: seba.svc
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: seba-svc
            port:
              number: 80
```

Commands:
```bash
openssl req -nodes -new -x509 -keyout seba.key -out seba.crt -subj "/CN=seba.svc"
kubectl run tmp-shell --rm -i --tty --image nicolaka/netshoot
> curl seba-svc.seba.svc.cluster.local
> curl -H "Host: seba.svc" http://<ingress-controller-ip>
```

#### Validate binaries against the checksum files

Links:
* [Install and Set Up kubectl on Linux](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

Commands:
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl.sha256"
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check
```

### 2 - Cluster Hardening

#### Service accounts permissions

Links:
* [Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
* [Service Account permissions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions)

Service account:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    kubernetes.io/enforce-mountable-secrets: "true"
  name: my-serviceaccount
  namespace: my-namespace
```

Role:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: pod-and-pod-logs-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list"]
```

Role binding:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: null
  name: my-serviceaccount-pod-and-pod-logs-reader
  namespace: my-namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-and-pod-logs-reader
subjects:
- kind: ServiceAccount
  name: my-serviceaccount
  namespace: my-namespace
```

Create new service account and new role:
```bash
kubectl create serviceaccount my-serviceaccount -n my-namespace --dry-run=client -o yaml

kubectl create role pod-and-pod-logs-reader \
  --verb=get --verb=list \
  --resource=pods --resource=pods/log \
  --namespace=my-namespace \
  --dry-run=client -o yaml

kubectl create rolebinding my-serviceaccount-pod-and-pod-logs-reader \
  --role=pod-and-pod-logs-reader \
  --serviceaccount=my-namespace:my-serviceaccount \
  --namespace=my-namespace \
  --dry-run=client -o yaml
```

Modify existing role:
```bash
kubectl -n my-namespace get sa
kubectl -n my-namespace get rolebindings.rbac.authorization.k8s.io -o yaml
kubectl -n my-namespace get pod-and-pod-logs-reader -o yaml
kubectl -n my-namespace edit pod-and-pod-logs-reader
```

### 3 - System Hardening

#### Protect K8s with AppArmor

Links:
* [Restrict a Container's Access to Resources with AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
* [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
* [AppArmor and Kubernetes](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor-and-Kubernetes)
* [Manage AppArmor profiles in Kubernetes with kube-apparmor-manager](https://sysdig.com/blog/manage-apparmor-profiles-in-kubernetes-with-kube-apparmor-manager/)

AppArmor profile to deny write:
```c
#include <tunables/global>

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}
```

Load profile into all nodes:
```bash
# This example assumes that node names match host names, and are reachable via SSH.
NODES=($(kubectl get nodes -o name))

for NODE in ${NODES[*]}; do ssh $NODE 'sudo apparmor_parser -q <<EOF
#include <tunables/global>

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}
EOF'
done
```

Pod with deny-write profile
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hello-apparmor
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: k8s-apparmor-example-deny-write
  containers:
  - name: hello
    image: busybox:1.28
    command: [ "sh", "-c", "echo 'Hello AppArmor!' && sleep 1h" ]
```

Other approach using metadata and annotations:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hello-restricted
  annotations:
    container.apparmor.security.beta.kubernetes.io/hello: localhost/k8s-apparmor-example-deny-write
spec:
  containers:
  - name: hello
    image: busybox
    command: [ "sh", "-c", "echo 'Hello AppArmor!' && sleep 1h" ]

```

### 4 - Minimize Microservice Vulnerabilities

#### Manage sensitive data with secrets

Links:
* [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
* [Define container environment variables using Secret data](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/#define-container-environment-variables-using-secret-data)
* [Managing Secrets using kubectl](https://kubernetes.io/docs/tasks/configmap-secret/managing-secret-using-kubectl/)

Encode password:
```bash
echo -n '39528$vdg7Jb' | base64
```

Define secret with base64 encoded password:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
data:
  username: bXktYXBw
  password: Mzk1MjgkdmRnN0pi
```

Container environment variable with data from secret:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: env-single-secret
spec:
  containers:
  - name: envars-test-container
    image: nginx
    env:
    - name: SECRET_USERNAME
      valueFrom:
        secretKeyRef:
          name: backend-user
          key: backend-username
```

Pod that access the secret through a volume:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-test-pod
spec:
  containers:
    - name: test-container
      image: nginx
      volumeMounts:
        # name must match the volume name below
        - name: secret-volume
          mountPath: /etc/secret-volume
          readOnly: true
  # The secret data is exposed to Containers in the Pod through a Volume.
  volumes:
    - name: secret-volume
      secret:
        secretName: test-secret
```

Commands:
```bash
kubectl create secret generic db-user-pass \
    --from-literal=username=admin \
    --from-literal=password='S!B\*d$zDsb='

kubectl create secret generic db-user-pass \
    --from-file=./username.txt \
    --from-file=./password.txt

kubectl get secrets

kubectl get secret db-user-pass -o jsonpath='{.data}'
echo 'UyFCXCpkJHpEc2I9' | base64 --decode

kubectl get secret db-user-pass -o jsonpath='{.data.password}' | base64 --decode

kubectl edit secrets db-user-pass
```

#### Run pod in secured runtime sandbox

Links:
* [Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/)
* [gVisor](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/)
* [gVisor Addon - instruction](https://github.com/kubernetes/minikube/blob/master/deploy/addons/gvisor/README.md)
* [Containerd Quick Start](https://gvisor.dev/docs/user_guide/containerd/quick_start/)

Runtime class:
```yaml
# RuntimeClass is defined in the node.k8s.io API group
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  # The name the RuntimeClass will be referenced by.
  # RuntimeClass is a non-namespaced resource.
  name: myclass 
# The name of the corresponding CRI configuration
handler: myconfiguration 
```

Usage of runtime class in pod:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  runtimeClassName: myclass
  # ...
```

### 5 - Supply Chain Security

#### Dockerfile security best practices

Links:
* [Dockerfile Best Practices](https://github.com/dnaprawa/dockerfile-best-practices)
* [General best practices for writing Dockerfiles](https://docs.docker.com/develop/develop-images/guidelines/)
* [Best practices for Dockerfile instructions](https://docs.docker.com/develop/develop-images/instructions/)
* [Security best practices](https://docs.docker.com/develop/security-best-practices/)
* [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
* [Top 20 Dockerfile best practices](https://sysdig.com/blog/dockerfile-best-practices/)

#### Kubernetes YAML files best practices

Links:
* [Configuration Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
* [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
* [Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

#### Scanning images for vulnerabilities

Links:
* [Trivy](https://aquasecurity.github.io/trivy/)

Commands:
```bash
brew install trivy

trivy image python:3.4-alpine
trivy fs --scanners vuln,secret,misconfig myproject/
trivy k8s --report summary cluster
```

#### Automate image vulnerability scanning

Links:
* [Admission Controllers Reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
* [Trivy Operator](https://github.com/devopstales/trivy-operator)
* [Using Kubernetes Admission Controllers](https://medium.com/@AbhijeetKasurde/using-kubernetes-admission-controllers-1e5ba5cc30c0)
* [Kubernetes Security Tools: OPA Gatekeeper & Trivy](https://medium.com/@noah_h/kubernetes-security-tools-opa-gatekeeper-trivy-5b613eb387ff)
* [Adding Trivy Scanner as custom Admission Controller](https://calvarado04.com/image-policy-webhooks-on-kubernetes-image-scanner-admission-controller/)
* [Certified Kubernetes Security Specialist (CKS) Preparation Part 7 — Supply Chain Security](https://jonathan18186.medium.com/certified-kubernetes-security-specialist-cks-preparation-part-7-supply-chain-security-9cf62c34cf6a)
* [Trivy Kubernetes Admission webhook](https://github.com/mmul-it/trivy-admission-webhook)

Image policy webhook:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    path: /etc/kubernetes/admission-control/imagepolicyconfig.yaml
```

Image policy config:
```yaml
imagePolicy:
  kubeConfigFile: /etc/kubernetes/admission-control/trivy-scanner.kubeconfig
  allowTTL: 50
  denyTTL: 50
  retryBackoff: 500
  defaultAllow: true # false, if deny images when image scanning service is not reachable
```

kubeconfig:
```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://trivy-scanner<my-domain>/scan
  name: okd
users:
- name: admin
  user: {}
preferences: {}
contexts:
- context:
    cluster: okd
    user: admin
  name: admin
current-context: admin
```

kube-api static pod:
```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint: 192.168.124.20:6443
  creationTimestamp: null
  labels:
    component: kube-apiserver
    tier: control-plane
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=192.168.124.20
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/admission-control/image-policy-webhook-conf.yaml
    [...]
    volumeMounts:
    [...]
    - mountPath: /etc/kubernetes/admission-control
      name: etc-kubernetes-admission-control
      readOnly: true
    [...]
  volumes:
  [...]
  - hostPath:
      path: /etc/kubernetes/admission-control
      type: DirectoryOrCreate
    name: etc-kubernetes-admission-control
```

### 6 - Monitoring, Logging and Runtime Security

#### Threat detection with Falco

Links:
* [The Falco Project -Cloud Native Runtime Security](https://falco.org/docs/)
* [Falco](https://github.com/falcosecurity/falco)
* [Kubernetes Security Tools: Falco](https://medium.com/@noah_h/kubernetes-security-tools-falco-e873831f3d3d)
* [Default and local rules files](https://falco.org/docs/rules/default-custom/)
* [Default rules](https://falco.org/docs/reference/rules/default-rules/)

Custom rule:
```yml
- rule: Detect privilege escalation in /tmp
  desc: Detect privilege escalationof binaries executed in /tmp
  condition: >
    evt.type = setresuid and evt.dir=> and
    proc.exepath startswith /tmp/
  output: "The binary %proc.name has tried to escalate privileges: %evt.args"
  priority: debug
```

Commands:
```bash
falco -r /path/to/my/rules1.yaml -r /path/to/my/rules2.yaml
```

#### Container Immutability

Links:
* [Best practices for operating containers - Immutability](https://cloud.google.com/architecture/best-practices-for-operating-containers#immutability)
* [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
* [Improve the security of pods running on Kubernetes](https://medium.com/datamindedbe/improve-the-security-of-pods-on-kubernetes-3e4a81534674)

Run as a non-root user:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: sec-ctx-demo
    image: busybox:1.28
    command: [ "sh", "-c", "sleep 1h" ]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
```

Read-only root file system:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  containers:
  - name: sec-ctx-demo
    image: busybox:1.28
    command: [ "sh", "-c", "sleep 1h" ]
    securityContext:
      readOnlyRootFilesystem: true
```

Run with allowPrivilegeEscalation=false:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    allowPrivilegeEscalation: false
  containers:
  - name: sec-ctx-demo
    image: busybox:1.28
    command: [ "sh", "-c", "sleep 1h" ]
    securityContext:
      allowPrivilegeEscalation: false
```

#### Audit Logging

Links:
* [Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
* [The Ultimate Guide to Audit Logging in Kubernetes: From Setup to Analysis](https://blog.kubesimplify.com/the-ultimate-guide-to-audit-logging-in-kubernetes-from-setup-to-analysis)
* [Kubernetes Audit Logging](https://docs.sysdig.com/en/docs/sysdig-secure/secure-events/kubernetes-audit-logging/)
* [How To Monitor Kubernetes Audit Logs](https://logrhythm.com/blog/how-to-monitor-kubernetes-audit-logs/)
* [How to monitor Kubernetes audit logs](https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/)
* [Monitor Audit Logs to Safeguard Your Kubernetes Infrastructure](https://www.crowdsec.net/blog/monitor-audit-logs-safeguard-kubernetes-infrastructure)
* [kube-apiserver Audit Configuration](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)

`kube-apiserver` flags:
```
  - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
  - --audit-log-path=/var/log/kubernetes/audit/audit.log
  - --audit-log-maxage=30
  - --audit-log-maxbackup=1
```

Example audit policy file `audit-policy.yaml`:
```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
  # Log "pods/log", "pods/status" at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]

  # Don't log requests to a configmap called "controller-leader"
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]

  # Don't log watch requests by the "system:kube-proxy" on endpoints or services
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API group
      resources: ["endpoints", "services"]

  # Don't log authenticated requests to certain non-resource URL paths.
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" # Wildcard matching.
    - "/version"

  # Log the request body of configmap changes in kube-system.
  - level: Request
    resources:
    - group: "" # core API group
      resources: ["configmaps"]
    # This rule only applies to resources in the "kube-system" namespace.
    # The empty string "" can be used to select non-namespaced resources.
    namespaces: ["kube-system"]

  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]

  # Log all other resources in core and extensions at the Request level.
  - level: Request
    resources:
    - group: "" # core API group
    - group: "extensions" # Version of group should NOT be included.

  # A catch-all rule to log all other requests at the Metadata level.
  - level: Metadata
    # Long-running requests like watches that fall under this rule will not
    # generate an audit event in RequestReceived.
    omitStages:
      - "RequestReceived"
```
