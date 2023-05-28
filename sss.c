#include <stdio.h>
#include <stdlib.h>
#include <libsecret/secret.h>

// Retrieve the secret using the specified schema and attribute
const char* get_secret(const char* schema, const char* attribute) {
    SecretService *service;
    GError *error = NULL;
    gchar *secret;

    service = secret_service_get_sync(SECRET_SERVICE_NONE, NULL, &error);
    if (error != NULL) {
        fprintf(stderr, "Error getting secret service: %s\n", error->message);
        g_error_free(error);
        return NULL;
    }

    secret = secret_password_lookup_sync(schema, NULL, &error,
        "attribute::%s", attribute);
    if (error != NULL) {
        fprintf(stderr, "Error retrieving secret: %s\n", error->message);
        g_error_free(error);
        return NULL;
    }

    return secret;
}

int main() {
    // Retrieve the secret with the specified schema and attribute
    const char* secret = get_secret("myapp/api_key", "myapp");
    if (secret == NULL) {
        fprintf(stderr, "Failed to retrieve secret\n");
        return 1;
    }

    // Use the secret
    printf("Secret: %s\n", secret);

    // Free the memory used by the secret
    g_free((gpointer)secret);

    return 0;
}