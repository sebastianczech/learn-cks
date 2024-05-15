# Certified Kubernetes Security Specialist (CKS)

## Links

* [Certification - Certified Kubernetes Security Specialist (CKS)](https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist/)
* [Open Source Curriculum for CNCF Certification Courses](https://github.com/cncf/curriculum)
* [Trivy - a comprehensive and versatile security scanner](https://github.com/aquasecurity/trivy)
* [Sysdig Documentation Hub](https://docs.sysdig.com/en/)
* [The Falco Project -Cloud Native Runtime Security](https://falco.org/docs/)
* [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)

## Tips

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

* [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
* [Acqua kube-bench](https://github.com/aquasecurity/kube-bench)
* [CIS Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

### 2 - Cluster Hardening

### 3 - System Hardening

### 4 - Minimize Microservice Vulnerabilities

### 5 - Supply Chain Security

### 6 - Monitoring, Logging and Runtime Security

