#!/usr/bin/env bash

function add_kong_helm_repo
{
    helm repo add kong https://charts.konghq.com
}

function helm_repo_update
{
    helm repo update
}

function install_helm
{
    helm upgrade --install kong kong/kong -f values_override_baked_in.yaml
}

function check_install
{
    kubectl port-forward svc/kong-kong-admin 8444 &
    curl https://localhost:8444/certificates
}

function install
{
    add_kong_helm_repo
    helm_repo_update
    install_helm
    check_install
}

install
