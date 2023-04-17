# Use CFSSL to generate certificates

More about [CFSSL here]("https://github.com/cloudflare/cfssl")

```

cd kubernetes\admissioncontrollers\introduction

docker run -it --rm -v ${PWD}:/work -w /work debian bash

apt-get update && apt-get install -y curl &&
curl -L https://github.com/cloudflare/cfssl/releases/download/v1.5.0/cfssl_1.5.0_linux_amd64 -o /usr/local/bin/cfssl && \
curl -L https://github.com/cloudflare/cfssl/releases/download/v1.5.0/cfssljson_1.5.0_linux_amd64 -o /usr/local/bin/cfssljson && \
chmod +x /usr/local/bin/cfssl && \
chmod +x /usr/local/bin/cfssljson

#generate ca in /tmp
cfssl gencert -initca ./tls/ca-csr.json | cfssljson -bare /tmp/ca

#generate certificate in /tmp
cfssl gencert \
  -ca=/tmp/ca.pem \
  -ca-key=/tmp/ca-key.pem \
  -config=./tls/ca-config.json \
  -hostname="aegorov-admission.default.svc.cluster.local,aegorov-admission,aegorov-admission.default.cluster.local,aegorov-admission.default.svc,localhost,127.0.0.1" \
  -profile=default \
  ./tls/ca-csr.json | cfssljson -bare /tmp/aegorov-admission

#make a secret
cat <<EOF > ./custom-webhook/templates/aegorov-admission-tls.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aegorov-admission-tls
type: Opaque
data:
  tls.crt: $(cat /tmp/aegorov-admission.pem | base64 | tr -d '\n')
  tls.key: $(cat /tmp/aegorov-admission-key.pem | base64 | tr -d '\n') 
EOF

#generate CA Bundle + inject into template
ca_pem_b64="$(openssl base64 -A <"/tmp/ca.pem")"

sed -e 's@${CA_PEM_B64}@'"$ca_pem_b64"'@g' <"mutatuion_template.yaml" \
    > custom-webhook/templates/mutatuingWebhookConfiguration.yaml
```