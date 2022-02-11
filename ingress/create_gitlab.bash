#!/bin/bash

helm repo update
helm -n rdbox-systems upgrade --install gitlab gitlab/gitlab -f values_for_gitlab.yaml
helm -n rdbox-systems upgrade --install gitlab gitlab/gitlab --set global.ingress.annotations."kubernetes\.io/ingress\.class"=ambassador -f values_for_gitlab.yaml
#    annotations:
#      kubernetes.io/ingress.class: ambassador
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kube-prometheus-stack-grafana
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-gitlab-exporter
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-gitlab-runner
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-gitlab-shell
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-minio
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-registry
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-sidekiq-all-in-1-v2
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-toolbox
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/gitlab-webservice-default

kubectl -n rdbox-systems apply -f values_for_gitlab-ssh.yaml

# Initial root password
kubectl -n rdbox-systems get secret gitlab-gitlab-initial-root-password -ojsonpath='{.data.password}' | base64 --decode ; echo