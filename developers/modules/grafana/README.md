# sync_grafana_dashboards

The sync_grafana_dashboards developed a script to generate a custom resource, `GrafanaDashboard`, for [GrafanaOperator](https://github.com/grafana-operator/grafana-operator/blob/master/documentation/api.md#grafanadashboard).

- Originally from: [helm\-charts/sync\_grafana\_dashboards\.py at main · prometheus\-community/helm\-charts · GitHub](https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/hack/sync_grafana_dashboards.py)
- It gets the JSON string for GrafanaDashboard from [kube\-prometheus/grafana\-dashboardDefinitions\.yaml at main · prometheus\-operator/kube\-prometheus](https://github.com/prometheus-operator/kube-prometheus/blob/main/manifests/grafana-dashboardDefinitions.yaml)．

## Preparation

```bash
cd rdbox/developers/modules/grafana
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

## Execution

```bash
./sync_grafana_dashboards.py
```

## Result

If `Finished` is displayed, it is successful. Check the output file.

```bash
Generating rules from https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/main/manifests/grafana-dashboardDefinitions.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/alertmanager-overview.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/apiserver.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/cluster-total.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/controller-manager.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/grafana-overview.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/k8s-resources-cluster.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/k8s-resources-namespace.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/k8s-resources-node.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/k8s-resources-pod.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/k8s-resources-workload.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/k8s-resources-workloads-namespace.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/kubelet.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/namespace-by-pod.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/namespace-by-workload.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/node-cluster-rsrc-use.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/node-rsrc-use.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/nodes-darwin.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/nodes.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/persistentvolumesusage.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/pod-total.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/prometheus-remote-write.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/prometheus.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/proxy.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/scheduler.yaml
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/workload-total.yaml
Generating rules from https://raw.githubusercontent.com/etcd-io/etcd/main/contrib/mixin/mixin.libsonnet
Generated ../../../helm/template-engine/templates/grafana/manifests/grafana-dashboard/etcd.yaml
Finished
```
