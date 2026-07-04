# Attested Key Provisioning for Kubernetes

*Securely provisioning PostgreSQL credentials on AKS through AMD SEV-SNP remote attestation.*

## 1 · Introduction

Running a database in Kubernetes requires solving a fundamental credential problem. A database process cannot start without a password, and that password must come from somewhere. The standard solution in Kubernetes is a _Secret object_, which stores the value in the cluster's internal key-value store where the workload can retrieve it at startup. This approach is widely used and operationally straightforward, but it carries a consequence that is easy to overlook. The secret exists inside the cluster before the workload ever runs. Any principal with sufficient permissions can read it, and in a managed cloud environment, the cloud provider operating the control plane has the technical means to access it as well.

This arrangement reflects an implicit trust assumption. It assumes that the cluster administrator, the cloud provider, and anyone who can reach the Kubernetes API are all trusted parties. In many deployments that assumption is acceptable. In confidential computing environments it is precisely the assumption that the security model is designed to eliminate.

Confidential computing hardware makes a fundamentally different model possible. Modern processors designed for confidential workloads can generate cryptographic proof of their own state, covering what hardware they run on and what software is executing inside the isolation boundary. This proof is produced by the CPU itself and cannot be manipulated by any software layer above it. It enables an inversion of the classical credential model. Instead of depositing a secret into the cluster before the workload starts, the environment hosting the workload can first demonstrate its trustworthiness, and only if that demonstration succeeds does the workload receive the credential. The cluster never holds the password.

This report works through that mechanism end to end. The theoretical part establishes the foundations needed to understand what the hardware guarantee actually provides, covering remote attestation as a protocol, AMD SEV-SNP as an implementation of hardware-enforced isolation, and Attested Key Provisioning as the pattern that connects the two to a practical secret-delivery problem. The practical part translates this into a complete, reproducible deployment on Azure Kubernetes Service, using CloudNativePG as the application context and Azure Key Vault as the external secret store.

The scope is deliberately specific. The deployment targets AKS with AMD EPYC Confidential VM nodes, uses Microsoft Azure Attestation as the verifier, and demonstrates the attestation pattern with a plain Kubernetes Pod running a PostgreSQL instance. The goal is not to propose a general solution for all confidential workloads but to make the mechanism concrete and to show, step by step, how a PostgreSQL instance can be started without the cluster ever holding its own password.

## 2 · Background

### 2.1 Container Orchestration with Kubernetes

Modern cloud applications rarely run as a single process on a single machine. Instead, they are decomposed into multiple services, each packaged as a container and deployed across a fleet of virtual machines. Managing this fleet manually, so deciding where each container runs, restarting it when it crashes and scaling it under load, quickly becomes unmanageable. Kubernetes addresses this by acting as an operating system for a cluster of machines. [1]

#### 2.1.1 Pods, Nodes, and Cluster Architecture

The three foundational abstractions are the Node, the Pod, and the Cluster. A **Node** is a single machine, typically a virtual machine in a cloud environment. A **Pod** is the smallest deployable unit, meaning it wraps one or more containers that share a network namespace and may share storage volumes. A **Cluster** is the full set of Nodes managed together.

Kubernetes does not operate by imperative commands. Operators declare intent through YAML manifests submitted to the API Server, which is the central entry point for all cluster operations. These manifests are persisted in `etcd`, a distributed key-value store that serves as the cluster's source of truth. The Controller Manager continuously reconciles actual state against desired state, triggering corrective actions when they diverge. The Scheduler decides which Node each Pod runs on, accounting for available resources and distribution constraints. In Azure's managed offering, **Azure Kubernetes Service** (AKS), Microsoft operates the entire control plane so that users interact with it only through the API.

*Figure 1: High-level layout of an AKS cluster: the control plane managed by Azure, worker nodes as individual VMs, and workload pods running on those nodes.*

#### 2.1.2 The Operator Pattern

Kubernetes knows how to schedule, restart, and scale containers. It does not know how to operate a PostgreSQL cluster. In practice this means how to bootstrap streaming replication, how to elect a new primary after failover, how to manage backups, or how to rotate credentials. This domain knowledge has to come from somewhere.

The Operator pattern extends Kubernetes with application-specific operational intelligence. [2] An Operator introduces one or more **Custom Resource Definitions** (CRDs), which are new resource types beyond the built-in Kubernetes vocabulary, and runs a controller that watches for instances of those types. When a user creates a custom resource, the Operator translates it into the concrete Kubernetes objects needed to fulfill the intent. The important consequence for consistency is that any configuration applied to a custom resource is automatically applied to every object the Operator creates from it.

**CloudNativePG** (CNPG) is a Kubernetes Operator designed specifically for PostgreSQL. [3] Instead of manually assembling StatefulSets, Services, and PersistentVolumeClaims, an administrator creates a single Cluster resource:

```yaml
# cluster.yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres-customer-1
spec:
  instances: 3
  storage:
    size: 20Gi
  superuserSecret:
    name: postgres-superuser-secret
```

The CNPG Operator picks up this object and translates it into three PostgreSQL Pods, three PersistentVolumeClaims, a read-write Service pointing to the primary, a read-only Service for the replicas, and the replication configuration that keeps them synchronized. Failover, backup scheduling, and credential management are handled automatically.

### 2.2 Secrets in Kubernetes

Every non-trivial application requires secrets at runtime. These could be database passwords, TLS private keys or API tokens. In Kubernetes, the standard mechanism for distributing these values to workloads is the Secret object. A Secret is created by a cluster administrator, stored in `etcd`, and can be projected into Pods as environment variables or mounted as files.

The security properties of **Kubernetes Secrets** are weaker than the name implies. By default, values are stored in `etcd` as plain base64-encoded strings, a reversible encoding rather than encryption. Even when `etcd` encryption at rest is configured, the API Server decrypts data on read, meaning the API Server itself always has access to cleartext values. Any principal with sufficient RBAC permissions can retrieve the full secret value with a single command:

```shell
kubectl get secret postgres-superuser-secret \
  -o jsonpath='{.data.password}' | base64 --decode
```

This threat model is often acceptable when the cluster administrator is fully trusted. In confidential computing scenarios, however, the explicit goal is to _reduce trust_ in privileged parties, including the cloud provider. In a managed environment like AKS, Microsoft operates the control plane and has the technical ability to access both `etcd` and the API Server. A secret stored there is outside the hardware trust boundary established by AMD SEV-SNP. Attested Key Provisioning, introduced in Section 3.3, closes this gap by ensuring that secrets never enter the cluster at all.

*Figure 2: A Kubernetes Secret is created by an administrator and read by the API Server in cleartext before being injected into a Pod. Any principal with sufficient cluster permissions can access the value at every step.*

## 3 · Technical Foundations

### 3.1 Remote Attestation

In a physical data center, an operator can walk up to a server, inspect its hardware, verify its configuration, and establish trust through direct observation. In a cloud environment, that option does not exist. The tenant cannot see the physical machine, cannot verify what firmware version it runs, and cannot confirm that the hypervisor beneath their virtual machine has not been modified. This leaves tenants with no choice but to extend unconditional trust to the cloud provider without any supporting evidence.

Remote attestation solves this problem. It is the process by which a computing environment generates cryptographic evidence about its own state, covering the hardware it runs on, the firmware that initialized it, and the software currently executing inside it. A remote party can verify this evidence without physical access and decide, based on what the evidence says, whether the environment is trustworthy enough to receive sensitive data or perform sensitive operations.

The key property that separates attestation from other forms of identity or authentication is that it is **hardware-rooted**. The evidence is generated and signed by a dedicated security processor inside the CPU that operates independently of the operating system, the hypervisor, and the cloud provider's infrastructure, hence it cannot be forged by software. This makes attestation the only mechanism that can establish trust even in the presence of a compromised or untrusted privileged layer.

> **Remote Attestation** — A process by which a computing environment generates cryptographic evidence of its hardware configuration, firmware state, and running software. A remote party verifies this evidence to decide whether the environment can be trusted before sharing sensitive data with it.

#### 3.1.1 Attester, Verifier, and Relying Party

The **IETF** **R**emote **AT**testation procedure**S** (RATS) architecture defines three roles that appear in every attestation system, regardless of the underlying hardware. [4]

The **Attester** is the entity whose trustworthiness is in question. It generates evidence about its own state in the form of a signed data structure and presents that evidence for evaluation.

The **Verifier** receives the evidence and evaluates it against a known-good reference. It checks that the cryptographic signatures are valid, that the firmware meets the required version, and that the measurement of the running software matches what is expected. If all checks pass, it issues an attestation result in the form of a signed token that asserts the Attester's trustworthiness.

The **Relying Party** consumes the attestation result and makes an access decision based on it. It does not evaluate the raw attestation evidence directly but it trusts the Verifier to have done that correctly and acts on the result.

This separation of roles matters for system design. The Verifier and the Relying Party can operate independently, and in security-sensitive deployments, they should be operated by different parties. Using a Verifier that is independent of the cloud provider ensures that even a malicious provider cannot unilaterally issue a valid attestation result for a workload that did not actually attest.

#### 3.1.2 The Attestation Flow

*Figure 3: The general attestation flow: the Relying Party issues a nonce, the Attester generates a signed hardware report and submits it to the Verifier, and the resulting attestation token is used to unlock access to a protected resource.*

Before any evidence is generated, the Relying Party produces a **nonce** (a random value used exactly once). The nonce is sent to the Attester and must appear inside the attestation report. This binding prevents replay attacks where an attacker could capture a valid report from a previous session and present it later.

The Attester passes the nonce to its hardware security processor, which constructs the attestation report. The report is a structured data object containing several categories of information. The security processor signs the entire report using a private key derived from hardware-unique secrets that never leave the chip. Because the signing key is hardware-bound, no software running on the system, including the operating system or hypervisor, can produce a valid signature on behalf of the processor.

The signed report is forwarded to the Verifier, which evaluates it against a configured policy. The Verifier always begins by checking the cryptographic integrity of the report itself, confirming that the signature is valid and that the signing key is certified through a chain that traces back to the hardware manufacturer. This chain is explained in more detail for AMD's implementation in Section 3.2.3. From there, the policy determines what else must hold. Depending on the deployment, this can include requirements on the firmware's security version, verification that the software measurement matches an expected reference, confirmation that the VM was not launched in a debuggable state, and checks against any other fields the report carries. If any requirement is not met, the Verifier rejects the evidence and the flow ends. If the policy is satisfied, the Verifier produces an attestation result, a **signed token** whose payload summarizes the verified claims and can be presented to any party that trusts the Verifier.

The Attester presents this token to the Relying Party. The Relying Party does not re-examine the raw hardware evidence. Instead, it evaluates the claims in the token against its own access policy. If the policy is satisfied, the Relying Party releases the resource.

### 3.2 AMD SEV-SNP on Azure

#### 3.2.1 Confidential Computing

Every security guarantee rests on some set of components that must function correctly for that guarantee to hold. This set is called the **Trusted Computing Base**, or TCB. In a conventional cloud virtual machine, the TCB is large. The hypervisor managing the VM, the host operating system it runs on, the firmware of the physical host, and the cloud provider's management infrastructure all sit beneath the guest and can, in principle, access its memory. The tenant has no way to verify whether any of these components have been modified or are operating honestly.

Confidential computing addresses this by redesigning the boundary. Instead of asking the tenant to trust the entire software stack beneath their VM, the hardware itself enforces isolation. AMD Secure Encrypted Virtualization with Secure Nested Paging (SEV-SNP) is AMD's implementation of this principle. [5] At the heart of SEV-SNP is the Platform Security Processor, an independent security processor embedded in every AMD EPYC CPU. It operates separately from the main CPU cores and cannot be accessed by the hypervisor, the guest operating system, or any other software layer above it. The PSP manages the cryptographic keys that encrypt each VM's memory and is the sole component authorized to produce signed attestation reports. Each confidential VM receives a unique encryption key, and all data moving between the CPU and RAM is encrypted and decrypted transparently, so that even a component with root access to the host sees only ciphertext.

The practical consequence is a dramatically smaller TCB. The hypervisor is no longer required to be trusted, meaning it can still manage scheduling and I/O, but it is explicitly outside the security boundary. The cloud provider's infrastructure drops out of the TCB as well. What remains is the CPU hardware itself and AMD's firmware running inside the security processor. A tenant who trusts AMD's silicon no longer needs to trust the cloud provider to keep their workload confidential.

> **Trusted Computing Base (TCB)** — The set of hardware and software components whose correct and uncompromised operation is required for a given security guarantee to hold. Components outside the TCB can fail or be malicious without affecting that guarantee.

> **Confidential Computing** — A hardware-enforced approach to cloud security that isolates a virtual machine's memory from the hypervisor, host operating system, and cloud provider. The trust boundary shrinks to the CPU hardware and its firmware, allowing tenants to run sensitive workloads on infrastructure they do not fully control.

#### 3.2.2 SEV-SNP on Azure

Running SEV-SNP on Azure introduces an additional firmware layer that does not appear in a generic SEV-SNP deployment. Azure confidential VMs include a component called the **Paravisor**, a small trusted firmware module that occupies the highest guest privilege level (VMPL 0) inside the VM. Above it, the guest operating system runs at a lower privilege level and cannot observe the Paravisor's memory.

The Paravisor's role is to handle the communication between the guest and Azure's hypervisor without requiring the guest to trust the hypervisor directly. This abstraction layer is called the Host Compatibility Layer (HCL). When the guest needs to interact with hardware devices or perform operations that require hypervisor cooperation, the HCL mediates these exchanges in a way that preserves the confidentiality guarantees of SEV-SNP. [7] As part of this compatibility role, the Paravisor also exposes a virtual Trusted Platform Module (vTPM) to the guest operating system. The attestation agent running inside the guest uses this vTPM interface to request SNP reports from the hardware, without requiring the guest to interact with the underlying measurement mechanisms directly.

From the guest's perspective, the underlying SEV-SNP mechanisms are not directly observable. The Paravisor abstracts them completely, which means there is no kernel interface or node-level check that confirms hardware isolation is active. The attestation report, once verified by MAA, is the authoritative evidence that the isolation boundary is in place.

#### 3.2.3 AMD Certificate Trust Chain

Section 3.1 described attestation reports as signed by a hardware-bound key that traces back to the hardware manufacturer. In AMD SEV-SNP, this key is called the Versioned Chip Endorsement Key, or VCEK. [6] The VCEK is derived inside the PSP from two inputs. The first is a secret unique to the physical chip that never leaves it, and the second is the current TCB version of the platform. Because the TCB version is part of the derivation, a chip running different firmware versions produces different VCEKs. This binding makes it impossible to present a report signed by a newer VCEK while actually running older, potentially vulnerable firmware.

*Figure 4: The AMD certificate trust chain. Both VCEK and VLEK are certified through the same AMD hierarchy, rooted in the publicly verifiable AMD Root Key.*

AMD issues a certificate for each chip's VCEK through its Key Distribution Service. This certificate is signed by the AMD SEV Key (ASK), which is in turn signed by the AMD Root Key (ARK). The ARK is a self-signed root certificate whose public key is published by AMD and independently verifiable. A verifier that holds AMD's public root key can walk the full chain from a VCEK certificate back to the ARK and confirm that a given report was signed by a genuine AMD chip running a specific firmware version, without contacting AMD at verification time.

Azure can also use a second key type called the VLEK (Versioned Loaded Endorsement Key), which is issued to the cloud provider rather than derived from the individual chip. It avoids exposing the chip-unique identity and supports operational scenarios such as live VM migration, while following the same AMD certificate hierarchy. [6]

#### 3.2.4 Microsoft Azure Attestation

Microsoft Azure Attestation (MAA) is Azure's implementation of the Verifier role described in Section 3.1.1. [8] It is a managed service that accepts SNP attestation reports, evaluates them against AMD's certificate infrastructure and configurable policies, and returns a signed JWT that downstream services can use to make access decisions without re-examining the raw hardware evidence.

When MAA receives a report, it performs the verification steps described in Section 3.1.2. The report carries a cryptographic hash of the VM's initial memory state at launch, called the launch measurement, which uniquely identifies the software stack running inside the CVM. It also carries a nonce in its report data field, which binds the report to this specific attestation session and prevents replay. MAA checks the signature, validates the certificate chain back to the AMD Root Key, verifies the TCB version against AMD's published advisories, and optionally compares the launch measurement against a registered reference value. [8]

A report that passes all checks results in a JWT signed with MAA's own private key. The token payload carries the attested claims as structured fields. Any service that trusts MAA can verify this token using MAA's published public key without making any further calls to AMD or inspecting the raw report.

### 3.3 Attested Key Provisioning

#### 3.3.1 From Attestation to Secret Delivery

Section 2.2 identified the core weakness of Kubernetes Secrets, which is that the secret exists inside the cluster before the workload ever starts, and any sufficiently privileged party can read it from etcd. Section 3.2 established that attestation can generate cryptographic proof of a workload's hardware and software state. The question this section answers is how these two pieces fit together into a practical security mechanism.

*Figure 5: In the classical model the secret is deposited into the cluster in advance. Attested Key Provisioning inverts this: the workload must first prove its trustworthiness before the secret is released.*

The fundamental shift is one of timing and direction. In the classical model, a secret is deposited into the environment before the workload runs, and the workload simply picks it up. Trust flows from the environment to the workload. In Attested Key Provisioning, this is inverted. The secret remains in an external store, controlled by a policy. The workload, when it starts, generates an attestation report, has it verified by a Verifier, and receives the secret only if the resulting attestation token satisfies the store's access policy. Trust must be established before the secret is released, not assumed.

The security consequences of this inversion are significant. Because the secret is never written to etcd or any other cluster-internal storage, it cannot be recovered from the cluster's persistent state, meaning a cluster administrator listing Secret objects, an attacker exfiltrating an etcd backup, or anyone inspecting a node's disks finds nothing, because nothing was ever deposited there. What the pattern does not prevent is runtime access through the Kubernetes API. While the pod is running, any principal with permission to execute commands inside it, for example via `kubectl exec`, can read the secret from the in-memory volume, just as it could read a password injected through a conventional Kubernetes Secret. The protection is therefore directed at secrets at rest and at the infrastructure beneath the cluster, not at runtime access by RBAC-privileged users. If the pod is restarted, perhaps due to a crash or a rescheduling event, the attestation flow runs again from scratch. At any point in time, the secret exists only in the memory of a pod that has successfully completed the attestation flow within the current session.

Keeping secrets out of etcd is, by itself, not unique to this pattern. Established tools such as the Secrets Store CSI Driver or the External Secrets Operator also deliver values from an external store like Key Vault to workloads, but they authorize the retrieval solely through workload identity. Attested Key Provisioning adds a hardware-rooted condition on top of that, meaning the hosting environment must first prove its own state through attestation before the secret is released.

A second precision concerns what the attestation evidence actually covers. The launch measurement in an SNP report is computed over the confidential VM's initial memory contents. On Azure CVMs these consist of the virtual firmware including the Paravisor, while the guest kernel and initial ramdisk are measured separately into the vTPM's PCRs and evaluated by MAA as part of its compliance check. In an AKS deployment the confidential VM is the worker node, so the report attests the node image, not the container running on it. Every pod scheduled on any compliant Azure CVM node therefore produces identical attestation evidence, regardless of which container image it runs. Attestation in this report consequently establishes that the environment hosting the workload is a genuine confidential VM. Binding the evidence to a specific container image requires container-level confidential computing, which the conclusion returns to.

#### 3.3.2 Two-Layer Authorization: Attestation and Workload Identity

Attestation establishes that a workload is running on trusted hardware with trusted software. What it does not establish on its own is which secret that specific workload instance is permitted to receive.

Consider a deployment where a hundred customer databases all run the same CloudNativePG image on the same cluster. Because the attestation evidence describes the hosting environment rather than the individual container, as established in Section 3.3.1, their attestation reports are indistinguishable from one another. A Key Vault policy based purely on attestation would therefore grant all of them access to all secrets stored in the vault, which is clearly not the intended behaviour since each database instance should only be able to retrieve the credentials belonging to its own customer.

This is where workload identity serves as a second, orthogonal layer of authorization. In Azure, each Kubernetes Pod can be associated with an Azure Managed Identity through the Workload Identity mechanism. [9] A Kubernetes Service Account is linked to a Microsoft Entra ID identity via OIDC federation, and pods that run under that service account receive short-lived Microsoft Entra ID tokens at runtime. When a request reaches Key Vault, it evaluates both inputs together. The attestation token establishes that the requesting workload is running trustworthy code on trusted hardware. The workload identity token establishes that this specific instance is the one authorized to access this specific secret.

Neither layer alone is sufficient. Attestation without identity cannot distinguish between the hundred customer databases. Identity without attestation provides no hardware-rooted guarantee that the entity presenting the token is actually running the expected software on an uncompromised platform. Together they close the authorization problem completely, combining proof of what is running with proof of which specific instance is permitted to act.

> **Azure Workload Identity** — A mechanism that links a Kubernetes Service Account to an Azure Managed Identity via OIDC federation. Pods running under the service account receive short-lived Microsoft Entra ID tokens, which can be presented to Azure services such as Key Vault alongside an attestation token to authorize access to specific resources.

#### 3.3.3 The Init Container Pattern for Secret Injection

Once the attestation and authorization mechanism is understood, the remaining question is where in the pod lifecycle the attestation flow should run. There are two candidates. A regular sidecar container runs alongside the main container for the full lifetime of the pod. An init container runs before the main container starts and exits once its work is complete.

A regular sidecar creates a timing problem. Kubernetes starts all containers in a pod roughly simultaneously, which means the main container might attempt to read the secret before the sidecar has completed attestation and written the value. This race condition requires additional coordination logic inside the main container, which is undesirable in a general setup where the main container, in this case the CloudNativePG-managed PostgreSQL process, is not written with attestation in mind.

An init container resolves this cleanly. Kubernetes guarantees that all init containers run to successful completion before any regular container in the pod is started. [1] The attestation init container performs the full flow. Only once it exits with a success code does Kubernetes start the PostgreSQL container, which reads the secret from the shared volume as part of its normal startup.

The **shared volume is configured as a tmpfs** mount, meaning it is backed by RAM and never written to disk. The secret therefore exists only in memory for as long as the pod runs. When the pod stops, the memory is released. If the pod restarts, the init container runs again, performing a fresh attestation flow and retrieving the secret anew. This ensures that the secret's lifetime inside the cluster is always bounded by the lifetime of a single, successfully attested pod instance.

## 4 · Practical Implementation

Now that we have established a solid theoretical foundation, from remote attestation and AMD SEV-SNP to Attested Key Provisioning in a Kubernetes environment, we can translate this into practice. The following steps walk through a complete, reproducible deployment on Azure, from cluster setup to a running CloudNativePG instance that retrieves its credentials exclusively through hardware-rooted attestation.

### 4.1 Architecture Overview

The deployment described in this section consists of three distinct layers that work together to implement the Attested Key Provisioning mechanism from Section 3.3.

*Figure 6: System components: the attestation init container inside the AKS cluster interacts with MAA, Key Vault, and Microsoft Entra ID. The secret reaches PostgreSQL exclusively through the in-memory tmpfs volume.*

The first layer is the **AKS cluster** itself. Its worker nodes are provisioned as `Standard_DC2as_v5` virtual machines, which are Azure's Confidential VM offering backed by AMD EPYC processors with SEV-SNP support. Only nodes of this family have the hardware necessary for the attestation flow to work.

The second layer is the **CloudNativePG** operator and the PostgreSQL workload. The operator is installed into the cluster and manages `Cluster` resource objects for production use. For the attestation demonstration in this walkthrough, however, a plain Kubernetes Pod is used rather than a CNPG-managed cluster. This choice is deliberate and explained in detail in Section 4.4.

The third layer consists of the Azure services that sit outside the cluster and form the trust infrastructure. **Microsoft Azure Attestation** serves as the Verifier, meaning it receives the SNP report from the init container, verifies the AMD certificate chain and TCB version, and returns a signed JWT. **Azure Key Vault** holds the PostgreSQL superuser password and releases it to any caller that presents a valid workload identity credential matching its access policy. The MAA token is not presented to Key Vault directly, but rather it is validated by the init container code before Key Vault is ever contacted, and the container exits with an error if the token does not satisfy the required claims. Microsoft Entra ID, through the Workload Identity mechanism, issues the short-lived identity tokens that pods receive by virtue of running under the designated service account.

The separation between what lives inside the cluster and what lives outside it is deliberate and central to the security model. Everything sensitive is external, so the secret never enters etcd, and the verification infrastructure is independent of the cluster's internal state. An attacker who compromises the cluster administrator account gains access to etcd and the Kubernetes API, but finds no secret there. The enforcement boundary for attestation sits in the init container code. A workload that does not pass the attestation checks cannot proceed to retrieve the secret even if it holds the correct managed identity credential. The security implications of this code-level boundary are examined in the conclusion.

### 4.2 AKS Cluster Setup with Confidential VM Nodes

**Prerequisites and a practical note on Azure quotas**

This setup requires an Azure subscription on the Pay-As-You-Go plan. Free trial accounts do not support the Confidential VM node sizes needed for AMD SEV-SNP. Before creating the cluster, a quota increase must be requested for the **Standard DCASv5 Family vCPUs** in the Azure Portal under Home › Quotas › My quotas. These requests are frequently rejected or delayed in popular regions. It is worth submitting requests in several locations in parallel (germanywestcentral, westeurope, and eastus are good starting points) and proceeding with whichever is approved first. If multiple subscriptions are active on the account, it is important to select the right Pay-As-You-Go plan for the quota requests.

*Screenshot 1: Azure Portal quota page (Home › Quotas › My quotas), filter Standard DCASv5 Family vCPUs, Pay-As-You-Go subscription, regions selected.*

When requesting the quota increase, keep in mind that one quota unit corresponds to one vCPU, and the `Standard_DC2as_v5` node size requires 2 vCPUs per node. Requesting a quota of 2 is therefore the minimum needed to run a single node, which is sufficient for this walkthrough. A real deployment with multiple nodes would require a proportionally higher quota.

*Screenshot 2: request outcome — 5 of 7 regions approved (Australia Central/East, Central US, Germany West Central, West US), 2 rejected (East US, East US 2).*

Once the quota is approved, install the Azure CLI and connect to your subscription:

```bash
az login
```

Create a resource group in the location where your quota was approved:

```bash
az group create \
  --name rg-snp-demo \
  --location germanywestcentral
```

Before creating the AKS cluster, the Azure subscription must have the `Microsoft.ContainerService` resource provider registered. On new subscriptions this step is often missing and causes the `az aks create` command to fail immediately. Register the provider and wait until it is active before proceeding:

```bash
az provider register --namespace Microsoft.ContainerService

# Check registration status — wait until output shows "Registered"
az provider show \
  --namespace Microsoft.ContainerService \
  --query "registrationState" \
  -o tsv
```

Create the AKS cluster with a Confidential VM node pool. The `--node-vm-size Standard_DC2as_v5` selects an AMD EPYC node with SEV-SNP support. The two flags `--enable-oidc-issuer` and `--enable-workload-identity` activate the OIDC endpoint and Workload Identity that Section 3.3.2 described as the second authorization layer:

```bash
az aks create \
  --resource-group rg-snp-demo \
  --name aks-snp-demo \
  --node-vm-size Standard_DC2as_v5 \
  --node-count 1 \
  --enable-oidc-issuer \
  --enable-workload-identity \
  --generate-ssh-keys
```

This command takes several minutes. Once it completes, download the credentials so that `kubectl` can reach the cluster:

```bash
az aks get-credentials \
  --resource-group rg-snp-demo \
  --name aks-snp-demo
```

```bash
kubectl get nodes
```

```output
NAME                                STATUS   ROLES    AGE     VERSION
aks-nodepool1-29189534-vmss000000   Ready    <none>   4m17s   v1.35.5
```

The node appears as a standard AKS worker node. Nothing in this output indicates that it is a Confidential VM. This is expected, and connects directly to the fact that the Paravisor abstracts the underlying SEV-SNP hardware completely from the guest's perspective, as described in Section 3.2.2.

**Setting up the identity and secrets infrastructure**

The same registration requirement applies to Azure Key Vault. A fresh subscription does not have the `Microsoft.KeyVault` provider active by default.

```bash
az provider register --namespace Microsoft.KeyVault
az provider show --namespace Microsoft.KeyVault --query "registrationState" -o tsv
```

Wait until the output reads `Registered` before proceeding.

Create an Azure Key Vault and store the PostgreSQL superuser password. Using `openssl rand` ensures the password is cryptographically random and not typed by hand:

```bash
az keyvault create \
  --name kv-snp-demo \
  --resource-group rg-snp-demo \
  --location germanywestcentral
```

By default, Azure Key Vault is created with RBAC authorization enabled. In this model, permissions are granted through standard Azure role assignments rather than per-vault Access Policies, and even the account that created the vault has no access to its secrets until an explicit assignment is made. To create and store the PostgreSQL password, the current account needs the `Key Vault Secrets Officer` role:

```bash
USER_ID=$(az ad signed-in-user show --query id -o tsv)
KV_ID=$(az keyvault show --name kv-snp-demo --resource-group rg-snp-demo --query id -o tsv)

az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee $USER_ID \
  --scope $KV_ID
```

Role assignments propagate through Microsoft Entra ID and can take up to a minute to take effect. After waiting briefly, the secret can be set:

```bash
az keyvault secret set \
  --vault-name kv-snp-demo \
  --name postgres-superuser-password \
  --value "$(openssl rand -base64 24)"
```

*Screenshot 3: Azure Portal, Key Vault with the stored postgres-superuser-password secret.*

Create the Managed Identity that the attestation init container will assume:

```bash
az identity create \
  --name id-postgres-attestation \
  --resource-group rg-snp-demo

IDENTITY_CLIENT_ID=$(az identity show \
  --name id-postgres-attestation \
  --resource-group rg-snp-demo \
  --query clientId -o tsv)

IDENTITY_OBJECT_ID=$(az identity show \
  --name id-postgres-attestation \
  --resource-group rg-snp-demo \
  --query principalId -o tsv)
```

The init container only needs to read the secret, never create or modify it. Assigning the `Key Vault Secrets User` role to the Managed Identity grants exactly that access and nothing more:

```bash
KV_ID=$(az keyvault show \
  --name kv-snp-demo \
  --resource-group rg-snp-demo \
  --query id -o tsv)

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id $IDENTITY_OBJECT_ID \
  --assignee-principal-type ServicePrincipal \
  --scope $KV_ID
```

Create a Kubernetes Service Account and link it to the Managed Identity via OIDC federation. This is the step that makes the second authorization layer work, meaning that when a pod runs under this service account on this cluster, Microsoft Entra ID will issue it a token for the Managed Identity.

```bash
kubectl create serviceaccount postgres-attestation-sa \
  --namespace default

kubectl annotate serviceaccount postgres-attestation-sa \
  azure.workload.identity/client-id=$IDENTITY_CLIENT_ID \
  --namespace default

OIDC_ISSUER=$(az aks show \
  --name aks-snp-demo \
  --resource-group rg-snp-demo \
  --query "oidcIssuerProfile.issuerUrl" -o tsv)

az identity federated-credential create \
  --name postgres-federation \
  --identity-name id-postgres-attestation \
  --resource-group rg-snp-demo \
  --issuer $OIDC_ISSUER \
  --subject system:serviceaccount:default:postgres-attestation-sa
```

### 4.3 CloudNativePG Installation via Operator

Installing the CNPG Operator is part of the complete setup and demonstrates the production context this walkthrough is situated in. [3] As Section 4.4 explains, the attestation demonstration uses a plain Kubernetes Pod rather than a CNPG-managed cluster. Nonetheless the operator is installed here to show the environment it would run in and to make the constraint tangible. The `kubectl apply` command below installs a patch release of the currently supported minor version (1.29 at the time of writing), registers the Cluster custom resource type, and starts the controller:

```bash
kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/releases/cnpg-1.29.0.yaml
```

Wait until the operator pod is running before proceeding:

```bash
kubectl get pods -n cnpg-system --watch
```

```output
NAME                                      READY   STATUS    RESTARTS   AGE
cnpg-controller-manager-ddb7496c6-5vnwg   0/1     Running   0          11s
cnpg-controller-manager-ddb7496c6-5vnwg   0/1     Running   0          15s
cnpg-controller-manager-ddb7496c6-5vnwg   1/1     Running   0          15s
```

### 4.4 The Attestation Init Container

As established in Section 3.3.3, the init container is the correct deployment pattern for this use case. Kubernetes guarantees that all init containers complete successfully before any regular container in the pod starts, which means the ordering guarantee is enforced by the container runtime itself rather than by coordination logic inside the application. The attestation agent runs, writes the secret to a shared tmpfs volume, and exits. Only then does PostgreSQL start and read the secret from that volume. The secret never touches etcd.

**The CNPG integration constraint**

CloudNativePG introduces a practical obstacle. The `Cluster` CRD manages the pod spec of each PostgreSQL instance internally, meaning when the Cluster manifest is applied, the operator generates the pod definitions itself and does not expose an `additionalInitContainers` field. The absence is a documented community issue [10]; the request was closed as "not planned", so native support is not on the project's roadmap as of the time of writing.

Three approaches exist for production environments that need to combine CNPG with pre-startup secret injection.

- **Kubernetes Job:** A Job runs the attestation flow before the Cluster is deployed and writes the result into a Kubernetes Secret. CNPG references this Secret via `spec.superuserSecret`. The ordering guarantee is maintained explicitly via `kubectl wait`. The trade-off is that the secret value does enter Kubernetes Secret storage and is therefore readable by cluster administrators, so the tmpfs guarantee from Section 3.3.3 does not hold.
- **Mutating Admission Webhook:** A webhook intercepts pod creation requests at the Kubernetes API level, before the pod spec reaches the kubelet, and injects an init container. This is the approach used by HashiCorp Vault Agent Injector and works transparently with operator-managed pods including CNPG. It preserves the full security model but requires a significant amount of additional infrastructure to deploy and operate.
- **Plain Kubernetes Pod:** The Cluster CRD is not used for the attested workload. A plain pod is deployed directly, giving full control over the pod spec. The init container pattern applies without restriction and the full security model is preserved. The trade-off is that the management automation CNPG provides is not available for this pod.

**This walkthrough uses a plain Kubernetes Pod** for the attestation demonstration. This is the approach that most faithfully implements the pattern described in Section 3.3.3, and it makes every component of the attestation flow directly visible without operator-level abstraction. A production deployment at scale would use the Mutating Webhook approach, which delivers the same security guarantee while preserving the operational benefits of CNPG.

**The attestation agent**

The agent performs three sequential steps. It requests an SNP attestation token from MAA via the vTPM interface, decodes the returned JWT, and verifies the claims before proceeding. Only if `x-ms-compliance-status` is `azure-compliant-cvm`, the VM is not in debug mode, and the token was issued within the last five minutes does the agent continue. If any check fails the container exits with a non-zero status before Key Vault is ever contacted.

The strict RATS model described in Section 3.1.2 requires the Relying Party to issue a nonce that the Attester must embed in its report. Key Vault has no mechanism to provide a nonce, so this binding cannot be achieved in this implementation. The agent instead checks the `iat` claim to ensure the token was issued within the last five minutes. This narrows the replay window rather than eliminating it. A token captured from any session older than five minutes fails the check, while a token captured within that window would still pass, because nothing binds the token to this specific pod startup. Since the agent requests a freshly signed token on every start, the check is a reasonable practical safeguard, but it remains weaker than a true nonce binding.

This is a code-level enforcement boundary, not a policy-level one. Key Vault itself does not independently require an attestation token and would accept a request from any workload holding the correct Managed Identity credential. Moving attestation enforcement to the policy layer requires either Azure Managed HSM with a Secure Key Release policy, which evaluates MAA tokens natively before releasing a key, or a custom intermediary service that validates both tokens before proxying the secret. Both options introduce additional infrastructure and are outside the scope of this walkthrough.

Create the build context and the two files:

```bash
mkdir attestation-agent && cd attestation-agent
nano attestation_agent.py   # paste from Appendix A
nano Dockerfile             # paste from Appendix A
```

Register the provider, create the registry, and build the image:

```bash
az provider register --namespace Microsoft.ContainerRegistry
az provider show --namespace Microsoft.ContainerRegistry \
  --query "registrationState" -o tsv  # wait for "Registered"

az acr create \
  --name acrsnpdemo \
  --resource-group rg-snp-demo \
  --sku Basic

az acr build \
  --registry acrsnpdemo \
  --image attestation-agent:latest .

az aks update \
  --resource-group rg-snp-demo \
  --name aks-snp-demo \
  --attach-acr acrsnpdemo

cd ..
```

The build takes approximately five minutes because Rust compiles the `cryptography` dependency from source.

**The Pod manifest**

Create `postgres-pod.yaml`. The `azure.workload.identity/use: "true"` label activates Workload Identity token injection for this pod. The `nodeSelector` ensures the pod lands on a Confidential VM node with the required hardware. The full manifest is in Appendix A.

```bash
nano postgres-pod.yaml      # paste from Appendix A
```

Apply the manifest:

```bash
kubectl apply -f postgres-pod.yaml
```

### 4.5 Attestation and Verification

After completing the Azure and Kubernetes prerequisites the goal is to confirm that the attestation flow runs correctly, the secret reaches the PostgreSQL container via the tmpfs volume, and no copy of the password ever lands in Kubernetes-managed storage.

Watch the pod start up to observe the init container sequence in real time:

```bash
kubectl get pods --watch
```

The pod transitions through `Init:0/1` while the attestation-agent init container is running, then briefly through `PodInitializing`, and finally reaches `Running` once PostgreSQL is ready.

Inspect the init container logs to confirm each step of the attestation flow completed correctly:

```bash
kubectl logs postgres-attested -c attestation-agent
```

```output
/usr/local/lib/python3.8/dist-packages/azure/identity/_internal/aadclient_certificate.py:7: CryptographyDeprecationWarning: Python 3.8 is no longer supported by the Python core team and support for it is deprecated in cryptography. The next release of cryptography will remove support for Python 3.8.
  from cryptography import x509
Starting attestation flow...
Attestation JWT received from MAA.
Attestation verified: compliance=azure-compliant-cvm, debuggable=False, token_age=0.3s
Secret written to /secrets/superuser-password. Init container complete.
```

The deprecation warning in the first two lines is expected and non-fatal. It reflects the base image's Python 3.8 dependency, noted as a pending update in the security assessment.

The attestation token issued by MAA for this session is reproduced and annotated in full in Appendix B. Three fields are directly relevant to the security argument.

`x-ms-compliance-status: "azure-compliant-cvm"` confirms that the Azure attestation service verified the complete boot chain before issuing the token, and `x-ms-sevsnpvm-is-debuggable: false` establishes that no debug interface is active at the hardware level. Both of these fields are actively validated by the init container before Key Vault is contacted. `x-ms-sevsnpvm-launchmeasurement` contains the SHA-384 digest of the VM's initial memory state at launch, the value a relying party would pin against a known-good reference to confirm that the correct, unmodified image is running inside the CVM.

Verify that the PostgreSQL container started and is accepting connections:

```bash
kubectl exec -it postgres-attested -- \
  psql -U postgres -c "SELECT version();"
```

```output
Defaulted container "postgres" out of: postgres, attestation-agent (init)
                                                       version
----------------------------------------------------------------------------------------------------------------------
 PostgreSQL 16.14 (Debian 16.14-1.pgdg13+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit
(1 row)
```

A successful query confirms that PostgreSQL initialized itself with the password from `/secrets/superuser-password` and started correctly. Note that `kubectl exec` connects through the local Unix socket, which the postgres image authenticates via trust, so the query itself does not exercise password authentication. The evidence lies in the startup, so if the password file were missing or malformed, PostgreSQL would have exited during initialization and the pod would be in `CrashLoopBackOff`.

Finally, verify the complete lifecycle of the secret across all three relevant locations. First, read the value directly from the tmpfs volume inside the running pod:

```bash
kubectl exec postgres-attested -- cat /secrets/superuser-password
```

```output
Defaulted container "postgres" out of: postgres, attestation-agent (init)
bw8GdJfPXnk0wGeN+xArjdqyRdN8DV6I
```

Second, read the original value from Key Vault to confirm they are identical:

```bash
az keyvault secret show \
  --vault-name kv-snp-demo \
  --name postgres-superuser-password \
  --query value -o tsv
```

```output
bw8GdJfPXnk0wGeN+xArjdqyRdN8DV6I
```

Third, confirm that no Kubernetes Secret object was created at any point:

```bash
kubectl get secrets
```

```output
No resources found in default namespace.
```

The three outputs tell a complete story. Steps one and two return identical values, confirming that the init container faithfully retrieved the secret from Key Vault and placed it unchanged in the tmpfs volume. Step three confirms the value never passed through Kubernetes-managed storage because etcd contains no Secret object holding the password. Its only copy outside Key Vault exists in the RAM of the running pod, provisioned fresh during the attestation session and erased when the pod terminates.

The first verification step also illustrates the runtime boundary discussed in Section 3.3.1, which said that a principal with exec permission on the pod can read the secret for as long as the pod is alive. The guarantee established here concerns cluster-managed storage and the infrastructure beneath the cluster, not runtime access through the Kubernetes API.

**Cleanup**

Confidential VM nodes accrue charges for as long as they run. Once the walkthrough is complete, deleting the resource group removes the cluster, the Key Vault, the container registry, and the managed identity in a single step:

```bash
az group delete --name rg-snp-demo --yes --no-wait
```

## 5 · Summary and Security Assessment

This report set out to show that hardware attestation can replace the trust assumptions that Kubernetes Secrets require, and the implementation confirms that claim. A PostgreSQL container on AKS received its superuser password exclusively through a hardware-attested init container, the Kubernetes namespace held no Secret object at any point, and the password existed only in the RAM of a running pod that had successfully completed the attestation flow.

The security properties that hold are worth stating precisely. The init container validates the MAA attestation token before contacting Key Vault and aborts if the token does not carry `azure-compliant-cvm` status, if the VM is in debug mode, or if the token was not issued within the last five minutes. A genuine SNP report signed by an AMD processor is therefore a mandatory step in the code path before any secret is retrieved, and a token from a previous session cannot be substituted for a fresh one once it is more than five minutes old. A software-level compromise of the cluster, even with full kubectl access, finds nothing to retrieve from etcd because nothing was deposited there, although exec access to a live pod still exposes the value for the duration of that pod's lifetime, as Section 3.3.1 made explicit. An attacker attempting to forge an SNP attestation report in software cannot succeed because the signing key lives inside the PSP, is derived from chip-unique secrets, and never leaves the processor. If the pod restarts, the attestation flow runs again from scratch with no cached copy remaining anywhere in the cluster.

Several residual trust requirements remain. The most consequential gap concerns where attestation is actually enforced. The init container validates the MAA token in code before accessing Key Vault, but Key Vault does not independently require an attestation token and will release the secret to any caller with the correct Managed Identity credential, regardless of whether it runs on attested hardware. The enforcement boundary is therefore the init container code itself, not the access policy. Moving attestation out of the code path and into the policy layer would require either Azure Managed HSM with a Secure Key Release policy, which evaluates MAA tokens natively before releasing a key, or a custom intermediary service that validates both tokens before proxying the secret. A second limitation is that the access policy does not verify the software running inside the CVM against a known-good reference. It grants access to any workload holding the correct managed identity credential, regardless of what hardware it runs on or what code is executing inside the isolation boundary. Closing this gap in production requires computing a reference value from the expected image artifacts and registering it as a required condition in the attestation policy. Even then, the launch measurement identifies the node image rather than the workload container, as Section 3.3.1 discussed. Extending the measured boundary to the container itself is the goal of Confidential Containers, where each pod runs in its own hardware-isolated utility VM and the attestation evidence covers the container layers and runtime configuration. On Azure this model is currently available through Confidential Containers on Azure Container Instances [11]. A Kata-based preview of the same concept for AKS was retired in March 2026 [12], which underlines that container-level attestation on managed Kubernetes remains an evolving area. MAA is also operated by Microsoft and sits on the critical path between the raw hardware evidence and the access decision. While MAA cannot forge the AMD hardware signature, a deployment that requires full independence from the cloud provider would need to substitute a third-party verifier.

Several implementation-level gaps remain. The attestation agent currently requires `privileged: true` to access the vTPM device, which grants broader permissions than the task actually needs, and a more precise approach would expose only the vTPM resource through a dedicated device plugin. The MAA token is decoded and its claims are validated against the required values, but the token signature is not verified against MAA's published public key. A production deployment should fetch MAA's JWKS endpoint and verify the signature before trusting any claim in the payload. Taken together with the absence of policy-level enforcement in Key Vault, this means the attestation gate is, in its current form, demonstrative rather than load-bearing. An attacker who obtains the Managed Identity credential bypasses the gate entirely by never running the agent, and one who controls the agent's environment faces claim checks on a token whose signature is not verified. In the implemented state, the effective access control over the secret therefore rests on Azure Workload Identity alone, meaning the attestation flow demonstrates how hardware evidence is obtained and evaluated, but turning it into an actual enforcement mechanism requires the signature verification described above combined with one of the policy-level options from Section 4.4. The base image dependency on Python 3.8 will require updating as library support for it is dropped. Finally, the full CNPG integration story remains unresolved. The Mutating Webhook approach, which would allow the attestation pattern to work with operator-managed pods while preserving the complete security model, is the natural next step but is not implemented here.

Two open questions point toward further work. The first concerns the Paravisor itself. Throughout this report, the Paravisor and the Host Compatibility Layer are treated as implicitly trusted components that mediate the vTPM interface on behalf of the workload, but their own integrity is never independently verified by anything in the attestation flow. Whether a workload can obtain cryptographic assurance about the firmware layer sitting beneath it is an active question, and the answer matters for the completeness of the trust argument. The second open question is secret rotation. The mechanism described here retrieves the secret once at pod startup and holds it in memory for the pod's lifetime. If the secret in Key Vault is rotated while the pod is running, the pod continues using the old value until it is restarted. A more complete design would include a way for the workload to re-attest and refresh its credentials without downtime, but that mechanism falls outside the scope of this walkthrough.

## References

[1] Kubernetes Project. _Kubernetes Documentation_. https://kubernetes.io/docs/home/

[2] Philips, B. (2016). _Introducing Operators: Putting Operational Knowledge into Software_. Red Hat Blog. https://www.redhat.com/en/blog/introducing-operators-putting-operational-knowledge-into-software

[3] CloudNativePG Contributors. _CloudNativePG Documentation_. https://cloudnative-pg.io/documentation/

[4] Birkholz, H., Thaler, D., Richardson, M., Smith, N., Pan, W. (2023). _Remote ATtestation procedureS (RATS) Architecture_. RFC 9334. IETF. https://www.rfc-editor.org/rfc/rfc9334

[5] AMD. (2020). _SEV-SNP: Strengthening VM Isolation with Integrity Protection and More_. AMD Whitepaper. https://docs.amd.com/v/u/en-US/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more

[6] AMD. (2024). _SEV Secure Nested Paging Firmware ABI Specification_, Rev. 1.55. https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf

[7] Microsoft. (2024). _About Azure confidential VMs_. Microsoft Learn. https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview

[8] Microsoft. (2024). _Azure Attestation overview_. Microsoft Learn. https://learn.microsoft.com/en-us/azure/attestation/overview

[9] Microsoft. (2024). _Use Microsoft Entra Workload ID on Azure Kubernetes Service_. Microsoft Learn. https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview

[10] CloudNativePG Contributors. _Init container and volumes binding support needed_ (Issue #8655). GitHub. https://github.com/cloudnative-pg/cloudnative-pg/issues/8655

[11] Microsoft. (2023). _Confidential containers on Azure_. Microsoft Learn. [https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers)

[12] Microsoft. (2025). _Confidential Containers (preview) with Azure Kubernetes Service (AKS)_. Microsoft Learn. [https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview](https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview)

## Appendix

### A · Attestation Agent: Full Source

The complete source of the attestation agent referenced in Section 4.4.

```python
# attestation_agent.py
from __future__ import annotations

import subprocess, os, sys, traceback, time, base64, json
from azure.identity import WorkloadIdentityCredential
from azure.keyvault.secrets import SecretClient

KEYVAULT_URL = os.environ["KEYVAULT_URL"]
SECRET_NAME  = os.environ["SECRET_NAME"]
OUTPUT_PATH  = os.environ["OUTPUT_PATH"]

# Maximum age of an attestation token in seconds. MAA tokens are valid for
# 8 hours, but requiring a freshly-issued token limits the window in which
# a captured token could be replayed.
MAX_TOKEN_AGE_SECONDS = 300  # 5 minutes


def get_jwt() -> str:
    """Request an SNP attestation token from MAA via the vTPM interface."""
    result = subprocess.run(
        ["/AttestationClient", "-o", "token"],
        capture_output=True, text=True, check=True
    )
    # AttestationClient may write status lines alongside the JWT.
    # JWTs always start with "eyJ"; take the last match in case the output
    # contains multiple candidates.
    jwt_lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("eyJ")
    ]
    if not jwt_lines:
        raise ValueError(
            "No JWT found in AttestationClient output: "
            + repr(result.stdout[:400])
        )
    return jwt_lines[-1]


def verify_attestation(jwt_str: str) -> None:
    """Decode the MAA JWT and enforce the minimum required security claims
    before this process is permitted to access the external secret store.

    This check runs inside the init container and acts as a code-level gate:
    the attestation flow must succeed and produce a compliant token or the
    container exits with a non-zero status before Key Vault is ever contacted.

    Note: this implementation decodes the token without verifying the MAA
    signature. A production deployment should fetch MAA's JWKS endpoint and
    verify the signature before trusting any claim in the payload.
    """
    segment = jwt_str.split(".")[1]
    segment += "=" * (-len(segment) % 4)
    claims = json.loads(base64.urlsafe_b64decode(segment))

    tee = claims.get("x-ms-isolation-tee", {})

    compliance = tee.get("x-ms-compliance-status", "")
    if compliance != "azure-compliant-cvm":
        raise ValueError(
            f"Attestation rejected: compliance status is '{compliance}', "
            "expected 'azure-compliant-cvm'"
        )

    if tee.get("x-ms-sevsnpvm-is-debuggable", True):
        raise ValueError("Attestation rejected: VM is running in debug mode")

    # Verify token freshness. A token older than MAX_TOKEN_AGE_SECONDS
    # is rejected even if it has not yet reached its exp timestamp,
    # so only a very recently issued token passes.
    iat = claims.get("iat", 0)
    exp = claims.get("exp", 0)
    now = time.time()

    if now > exp:
        raise ValueError(f"Attestation token has expired (exp={exp}, now={now:.0f}).")

    age = now - iat
    if age > MAX_TOKEN_AGE_SECONDS:
        raise ValueError(
            f"Attestation token is too old: age {age:.0f}s exceeds limit of "
            f"{MAX_TOKEN_AGE_SECONDS}s. Possible replay attack."
        )

    print(
        f"Attestation verified: compliance={compliance}, "
        f"debuggable={tee.get('x-ms-sevsnpvm-is-debuggable')}, "
        f"token_age={age:.1f}s"
    )


def get_secret() -> str:
    credential = WorkloadIdentityCredential()
    client = SecretClient(vault_url=KEYVAULT_URL, credential=credential)
    return client.get_secret(SECRET_NAME).value


def main():
    print("Starting attestation flow...")
    jwt = get_jwt()
    print("Attestation JWT received from MAA.")
    verify_attestation(jwt)
    secret = get_secret()
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        f.write(secret)
    print(f"Secret written to {OUTPUT_PATH}. Init container complete.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        tb = traceback.format_exc()
        print(tb, file=sys.stderr)
        try:
            with open("/dev/termination-log", "w") as f:
                f.write(tb[:4096])
        except Exception:
            pass
        sys.exit(1)
```

```dockerfile
# Dockerfile
FROM mcr.microsoft.com/acc/samples/cvm-attestation:1.1 AS attestation-base

FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

COPY --from=attestation-base /AttestationClient /AttestationClient
COPY --from=attestation-base /usr/lib/azguestattestation1/ /usr/lib/azguestattestation1/

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    build-essential libssl-dev libffi-dev \
    libcurl4 ca-certificates \
  && ln -s /usr/lib/azguestattestation1/libazguestattestation.so.1.0.2 \
           /usr/lib/libazguestattestation.so.1 \
  && ldconfig \
  && pip3 install --upgrade pip \
  && pip3 install --no-cache-dir azure-keyvault-secrets azure-identity \
  && rm -rf /var/lib/apt/lists/*

COPY attestation_agent.py /app/attestation_agent.py
ENTRYPOINT ["python3", "/app/attestation_agent.py"]
```

```yaml
# postgres-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: postgres-attested
  namespace: default
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: postgres-attestation-sa
  nodeSelector:
    kubernetes.azure.com/security-type: ConfidentialVM
  initContainers:
    - name: attestation-agent
      image: acrsnpdemo.azurecr.io/attestation-agent:latest
      securityContext:
        privileged: true
      env:
        - name: KEYVAULT_URL
          value: "https://kv-snp-demo.vault.azure.net"
        - name: SECRET_NAME
          value: "postgres-superuser-password"
        - name: OUTPUT_PATH
          value: "/secrets/superuser-password"
      volumeMounts:
        - name: secrets-vol
          mountPath: /secrets
        - name: tpmrm0
          mountPath: /dev/tpmrm0
        - name: tcg
          mountPath: /sys/kernel/security
  containers:
    - name: postgres
      image: postgres:16
      env:
        - name: POSTGRES_PASSWORD_FILE
          value: /secrets/superuser-password
      volumeMounts:
        - name: secrets-vol
          mountPath: /secrets
  volumes:
    - name: secrets-vol
      emptyDir:
        medium: Memory  # tmpfs: stored in RAM, never written to disk
        sizeLimit: 1Mi  # the volume only ever holds a single short password
    - name: tpmrm0
      hostPath:
        path: /dev/tpmrm0
    - name: tcg
      hostPath:
        path: /sys/kernel/security
```

### B · Annotated Attestation Report

The MAA attestation token issued during the session in Section 4.5, reproduced in full with inline annotations. Values are truncated for readability.

```json
{
  // ─── Standard JWT claims ───────────────────────────────────────

  "iss": "https://sharedeus2.eus2.attest.azure.net",
  // MAA regional endpoint that signed this token. A relying party
  // should pin the expected issuer in its verification logic.

  "iat": 1782812454,
  "exp": 1782841254,
  // 8-hour validity window. Tokens are short-lived by design;
  // exp must be verified before trusting any claim.

  "jti": "56c86041...",
  // Unique token ID — usable for audit logging or replay prevention.

  // ─── Azure VM security posture ─────────────────────────────────

  "secureboot": true,
  // UEFI Secure Boot was enforced: bootloader and kernel were verified
  // against the platform key database before execution.

  "x-ms-azurevm-debuggersdisabled": true,
  // Kernel and hypervisor debuggers are disabled at runtime.

  "x-ms-azurevm-attested-pcr-values": {
    "pcr0": "Exd6ZT...", // CRTM, BIOS, host firmware
    "pcr1": "A+iphk...", // platform configuration
    "pcr2": "PUWM/l...", // option ROM code
    "pcr3": "PUWM/l...", // option ROM data
    "pcr4": "U1YyHY...", // bootloader
    "pcr5": "NVCj+t...", // GPT / partition table
    "pcr6": "4mTyh9...", // state transitions
    "pcr7": "OyDgIk..."  // Secure Boot policy and key databases
    // PCRs 0–7 accumulate hash-chained measurements of each boot stage.
    // Any modification to a measured component produces a different value.
  },

  "x-ms-azurevm-osdistro": "Ubuntu",
  "x-ms-azurevm-osversion-major": 20,
  "x-ms-azurevm-osversion-minor": 4,
  // AKS node OS: Ubuntu 20.04.

  "x-ms-azurevm-vmid": "4DD635C3-FC7C-4522-8273-066136DC604E",

  // ─── SEV-SNP hardware isolation layer ──────────────────────────
  // Claims below are signed by the AMD VCEK

  "x-ms-isolation-tee": {

    "x-ms-attestation-type": "sevsnpvm",
    // TEE type: AMD SEV-SNP. Root of trust is the AMD certificate
    // chain (ARK → ASK → VCEK).

    "x-ms-compliance-status": "azure-compliant-cvm",
    // Azure verified the full boot chain against its reference values.
    // Primary relying-party anchor: secret release should be gated
    // on this field being present and equal to "azure-compliant-cvm".

    "x-ms-sevsnpvm-chip-family": "Genoa",
    // AMD EPYC Genoa (Zen 4). The chipid field uniquely identifies
    // the physical die. VCEK is derived from it.
    "x-ms-sevsnpvm-chipid": "74bac9f6...",

    "x-ms-sevsnpvm-is-debuggable": false,
    // CRITICAL. Debug mode is disabled at the hardware level. If true,
    // a hypervisor could read decrypted guest memory, directly voiding
    // the SEV-SNP confidentiality guarantee.

    "x-ms-sevsnpvm-launchmeasurement":
      "15b1e5568572f6c648aa48288294bcdf...",
    // SHA-384 digest computed by the AMD PSP over the VM's initial
    // memory pages at launch (on Azure CVMs: the virtual firmware
    // including the Paravisor; kernel and initrd are measured into
    // the vTPM PCRs above). A relying party computes the same hash
    // from known-good image artifacts and compares it here.

    "x-ms-sevsnpvm-reportdata":
      "933f6b8e5a0047c6929eab21...6ae6f75" +
      "000000000000000000000000...000000",
    // 64-byte REPORT_DATA field. The first 32 bytes are the nonce
    // written by AttestationClient to the vTPM NV-Index before
    // requesting the SNP report. MAA verifies freshness via this nonce.

    // ─── Security Version Number chain ───────────────────────────
    "x-ms-sevsnpvm-microcode-svn": 88,  // AMD CPU microcode
    "x-ms-sevsnpvm-snpfw-svn":     27,  // SEV-SNP firmware
    "x-ms-sevsnpvm-bootloader-svn":10,  // UEFI bootloader
    "x-ms-sevsnpvm-guestsvn":   65547,  // guest image version
    // Relying parties can enforce minimum SVNs to reject VMs running
    // outdated, potentially vulnerable components.

    "x-ms-sevsnpvm-migration-allowed": false,
    // Live migration is not permitted

    "x-ms-runtime": {
      "keys": [
        { "kid": "HCLAkPub", "key_ops": ["sign"], ... },
        // HCL Attestation Key: allows a relying party to verify
        // subsequent signatures from this CVM without a new attestation.
        { "kid": "HCLEkPub", "key_ops": ["encrypt"], ... }
        // HCL Encryption Key: a relying party wraps a secret with this
        // key so only this specific CVM instance can decrypt it
      ],
      "vm-configuration": {
        "secure-boot": true,
        "tpm-enabled": true,
        "tpm-persisted": true  // vTPM state survives reboots
      }
    }
  },

  // ─── Policy and outer runtime ──────────────────────────────────

  "x-ms-policy-hash": "QsNi9UE365SgcskuV_a4p-uFQyGlNcIlQkrsi0UIy7o",
  // Hash of the MAA policy evaluated at issuance, which lets auditors
  // verify which policy version was in effect for this attestation.

  "x-ms-runtime": {
    "client-payload": { "nonce": "NGE3ZjliMmM4ZTFk...WM2ZDc=" },
    // Client nonce from AttestationClient
	
    "keys": [
      { "kid": "TpmEphemeralEncryptionKey", "key_ops": ["encrypt", "verify"], ... }
      // Ephemeral vTPM key for this session. A relying party can encrypt
      // a response with this key; only the vTPM inside this CVM can
      // unwrap it, enabling secure secret delivery over an untrusted channel.
    ]
  },

  "x-ms-ver": "1.0"
}
```