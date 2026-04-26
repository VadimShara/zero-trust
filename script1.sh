until curl -sf http://localhost:8080/realms/master > /dev/null; do
  echo "waiting for Keycloak..."; sleep 5
done
echo "Keycloak is ready"