#!/usr/bin/env bash

# Copyright (c) 2019 MyBack.space
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

usage() {
    echo -e "
This script generates a certificate suitable for use with the webhook
admission controller, either self-signed or signed by the k8s CA via the 
CertificateSigningRequest API.
NOTE: USE SELF-SIGNED CERTIFICATE FOR DEMO PURPOSES ONLY. IN PRODUCTION WORKLOADS USE CERTIFICATE SIGNED BY K8S.

usage: $0 [OPTIONS]
The following flags are required.
        -d, --crt-days          Number of days valid certifficate. For use with self-signed certificates. Default 365.
        -D, --ca-days           Number of days valid CA certificate. For use with self-signed certificates. Default 3650.
        -o, --out-dir           Path to save keys and certificates. Default \"./pki\"
        -n, --namespace         Namespace name. Use for automatic generate DNS. Default \"default\"
        -s, --service-name      Service name. \033[31mRequired\033[0m. Use only k8s service name. Automatic generate DNS with .{namespace} and .{namespace}.svc
        -S, --sign              Create self-signed certificate. If you use this option you can set --service-name with multiple FQDN, separated by commas.
        -u, --subj              Subject for certificate. Used ca-cubj if not set.
        -U, --ca-subj           Subject for CA certificate. \033[31mRequired\033[0m.
"
}

ssl::generate::key() {
    local TLS_PATH=${1}
    local BITS=${2:-2048}

    openssl genrsa -out "${TLS_PATH}/server.key" "${BITS}"
}

ssl::generate::request() {
    local TLS_PATH=${1}
    local SUBJECT=${2}

    openssl req -new -key "${TLS_PATH}/server.key" -out "${TLS_PATH}/server.csr" \
            -config "${TLS_PATH}/ssl.conf" -subj "${SUBJECT}"
}

ssl::signed::self() {
    local TLS_PATH=${1}
    local CA_DAYS=${2}
    local CRT_DAYS=${3}
    local SUBJECT=${4}

    openssl req -new -x509 -nodes -days ${CA_DAYS} -keyout "${TLS_PATH}/ca.key" \
            -out "${TLS_PATH}/ca.crt" -config "${TLS_PATH}/ssl.conf" \
            -subj "${SUBJECT}"

    openssl x509 -days ${CRT_DAYS} -req -in "${TLS_PATH}/server.csr" -CA "${TLS_PATH}/ca.crt" \
            -CAkey "${TLS_PATH}/ca.key" -CAcreateserial -CAserial "${TLS_PATH}/crt.srl" -out "${TLS_PATH}/server.crt" \
            -extensions v3_req -extfile "${TLS_PATH}/ssl.conf"
}

ssl::signed::k8s() {
    local TLS_PATH=${1}
    local CSR_NAME=${2}

    # clean-up any previously created CSR for our service. Ignore errors if not present.
    kubectl delete csr "${CSR_NAME}" 2>/dev/null || true

    # create server cert CSR
    cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: ${CSR_NAME}
spec:
  groups:
    - system:authenticated
  request: $(base64 < "${TLS_PATH}/server.csr" | tr -d '\n')
  usages:
    - digital signature
    - key encipherment
    - server auth
EOF

    # verify CSR has been created
    set +e
    while true; do
        if kubectl get csr ${CSR_NAME} 2>/dev/null; then
            break
        fi
    done

    kubectl certificate approve "${CSR_NAME}"

    # verify certificate has been signed
    for _ in $(seq 10); do
        ssl_crt=$(kubectl get csr "${CSR_NAME}" -o jsonpath='{.status.certificate}')

        if [ -n "${ssl_crt}" ]; then
            break
        fi
        sleep 1
    done
    set -e

    if [ -z "${ssl_crt}" ]; then
        echo "ERROR: After approving csr ${CSR_NAME}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
        exit 1
    fi

    echo "${ssl_crt}" | base64 --decode > "${TLS_PATH}/server.crt"
}

ssl::generate::conf() {
    local TLS_PATH=${1}

    cat << EOF > "${TLS_PATH}/ssl.conf"
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
;C=Country
;ST=State
;L=Location
;O=Organization
;OU=Organizational Unit
;CN=Common Name
;emailAddress=admin@example.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
EOF

    IFS=, read -r -a CN <<<"${2}"
    for i in "${!CN[@]}"; do
        echo "DNS.$((i + 1)) = ${CN[i]}" >> "${TLS_PATH}/ssl.conf"
     done

}

main() {
    # Required options
    local SERVICE=''
    local CA_SUBJ=''
    # ----------------

    local DIR='./pki'
    local SIGN_TYPE='1'
    local NAMESPACE='default'
    local CA_DAYS=3650
    local CRT_DAYS=365
    local CRT_SUBJ=''

    while getopts 'd:D:h:n:o:s:Su:U:-:' opt; do
        case ${opt} in
            d) CRT_DAYS="${OPTARG}" ;;
            D) CA_DAYS="${OPTARG}" ;;
            n) NAMESPACE="${OPTARG}" ;;
            o) DIR="${OPTARG}" ;;
            s) SERVICE="${OPTARG}" ;;
            S) SIGN_TYPE='2' ;;
            u) CRT_SUBJ="${OPTARG}" ;;
            U) CA_SUBJ="${OPTARG}" ;;
            h) usage
               exit 0
               ;;
            -) LONG_OPTARG="${OPTARG#*=}"
                case $OPTARG in
                    ca-days) CA_DAYS="${OPTARG}" ;;
                    ca-subj) CA_SUBJ="${OPTARG}" ;;
                    crt-days) CRT_DAYS="${OPTARG}" ;;
                    namespace) NAMESPACE="${OPTARG}" ;;
                    help) usage
                          exit 0
                          ;;
                    out-dir) DIR="${OPTARG}" ;;
                    service-name) SERVICE="${OPTARG}" ;;
                    sign) SIGN_TYPE='2' ;;
                    subj) CRT_SUBJ="${OPTARG}" ;;
                    *) echo "Unknown option -- ${OPTARG}"
                       usage
                       exit 1
                       ;;
                esac ;;
            *) echo "Unknown option -- ${OPTARG}"
               usage
               exit 1
               ;;
        esac
    done

    if [ -z "${SERVICE}" ]; then
        echo "Service name is required"
        usage
        exit 1
    fi

    if [ -z "${CA_SUBJ}" ]; then
        echo "CA subject is required"
        usage
        exit 1
    fi

    if [ -z "${CRT_SUBJ}" ]; then
        CRT_SUBJ="${CA_SUBJ}"
    fi

    local ALL_CN=""
    if [ "${SIGN_TYPE}" = '2' ]; then
        ALL_CN+="${SERVICE}"
    else
        ALL_CN+="${SERVICE},"
        ALL_CN+="${SERVICE}.${NAMESPACE},"
        ALL_CN+="${SERVICE}.${NAMESPACE}.svc"
    fi

    if [ ! -d "${DIR}" ]; then
        mkdir -p "${DIR}"
    fi

    ssl::generate::conf "${DIR}" "${ALL_CN}"
    ssl::generate::key "${DIR}"
    ssl::generate::request "${DIR}" "${CA_SUBJ}"

    if [ "${SIGN_TYPE}" = '2' ]; then
        ssl::signed::self "${DIR}" ${CA_DAYS} ${CRT_DAYS} "${CRT_SUBJ}"
    else
        ssl::signed::k8s "${DIR}" "${SERVICE}.${NAMESPACE}"
    fi

}

main "$@"
