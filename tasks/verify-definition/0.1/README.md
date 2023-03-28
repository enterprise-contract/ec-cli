# Verify Definition Task

This task is used to verify any valid YAML or JSON

## Install the task
kubectl apply -f https://raw.githubusercontent.com/hacbs-contract/ec-cli/main/tasks/verify-definition/0.1/verify-definition.yaml

## Parameters
### Required
* **DEFINITION**: The definition(s) to validate. This can be a yaml or json file, the files' contents
        or a directory containing the definition files. 
* **POLICY_SOURCE**: The source containing the policy files.
### Optional
* **NAMESPACE**: An optional policy package namespace.
* **POLICY_LIB**: The source containing the policy files libraries.
* **POLICY_DATA**: The source containing the policy files configuration data.
* **HOMEDIR**: Value for the HOME environment variable.

## Usage
This TaskRun runs the Task to verify the JSON string '{"kind": "Task"}'.

```yaml
---
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  generateName: verify-definition-run-
spec:
  params:
  - name: HOMEDIR
    value: /tekton/home
  - name: DEFINITION
    value: '{"kind": "Task"}'
  - name: NAMESPACE
    value: policy.task.kind
  - name: POLICY_SOURCE
    value: git::github.com/hacbs-contract/ec-policies//policy/task
  resources: {}
  serviceAccountName: default
  taskRef:
    resolver: bundles
    params:
    - name: bundle
      value: ${TASK_BUNDLE_REF}
    - name: name
      value: verify-definition
    - name: kind
      value: task
  timeout: 10m
```



