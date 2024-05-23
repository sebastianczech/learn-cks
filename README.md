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

Commands:
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

### 6 - Monitoring, Logging and Runtime Security

