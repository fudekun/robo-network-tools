#!/bin/bash

kind create cluster --config kind_cluster.yaml
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"

