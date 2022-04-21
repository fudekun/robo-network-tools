#!/usr/bin/env bash
set -euo pipefail

helm repo update
helm -n gitlab upgrade --install gitlab gitlab/gitlab \
  --create-namespace \
  -f values_for_gitlab.yaml
helm -n gitlab upgrade gitlab gitlab/gitlab \
  --set global.ingress.annotations."kubernetes\.io/ingress\.class"=ambassador \
  -f values_for_gitlab.yaml
#    annotations:
#      kubernetes.io/ingress.class: ambassador
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-gitlab-exporter
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-gitlab-runner
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-gitlab-shell
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-minio
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-registry
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-sidekiq-all-in-1-v2
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-toolbox
kubectl wait --timeout=180s -n gitlab --for=condition=available deployment/gitlab-webservice-default


kubectl -n gitlab apply -f values_for_gitlab-ssh.yaml

# Initial root password
kubectl -n gitlab get secret gitlab-gitlab-initial-root-password -ojsonpath='{.data.password}' | base64 --decode ; echo