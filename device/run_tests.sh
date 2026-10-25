cd /home/arthur/Documentos/UNB/TCC/wireguard-go/device

TESTS=$(grep -hEo '^func[[:space:]]+Test[[:alnum:]_]*' device_test.go noise_test.go mldsa_test.go \
  | awk '{print $2}' \
  | paste -sd'|' -)

go test -v -run "^($TESTS)$"
