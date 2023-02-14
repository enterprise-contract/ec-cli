# Verify Enterprise Contract Task

This task verifies a signature and attestation for an image and then runs a policy against the image's attestation using the ```ec validate image``` command.

## Install the task
kubectl apply -f https://raw.githubusercontent.com/hacbs-contract/ec-cli/main/task/0.1/verify-enterprise-contract.yaml

## Parameters
### Required
* **IMAGES**: A JSON formatted list of images. 
### Optional
* **POLICY_CONFIGURATION**: Name of the policy configuration (EnterpriseContractPolicy
        resource) to use. `namespace/name` or `name` syntax supported. If
        namespace is omitted the namespace where the task runs is used.
* **PUBLIC_KEY**: Public key used to verify signatures. Must be a valid k8s cosign
        reference, e.g. k8s://my-space/my-secret where my-secret contains
        the expected cosign.pub attribute.
* **REKOR_HOST**: Rekor host for transparency log lookups
* **SSL_CERT_DIR**: Path to a directory containing SSL certs to be used when communicating
        with external services.
* **STRICT**: Fail the task if policy fails. Set to "false" to disable it.
* **HOMEDIR**: Value for the HOME environment variable.


## Usage

This TaskRun runs the Task to verify an image. This assumes a policy is created and stored on the cluster with hte namespaced name of `enterprise-contract-service/default`. For more information on creating a policy, refer to the Enterprise Contract [documentation](https://hacbs-contract.github.io/ecc/main/index.html).

```yaml
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  name: verify-enterprise-contract
spec:
  taskRef:
    name: verify-enterprise-contract
  params:
  - name: IMAGES
    value: '{"components": ["containerImage": "quay.io/example/repo:latest"]}'
```



