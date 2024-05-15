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

### 2 - Cluster Hardening

### 3 - System Hardening

### 4 - Minimize Microservice Vulnerabilities

### 5 - Supply Chain Security

### 6 - Monitoring, Logging and Runtime Security

