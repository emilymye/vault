package gcputil

import (
	"cloud.google.com/go/compute/metadata"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"google.golang.org/api/iam/v1"
	"strconv"
	"time"
	"net/http"
	"src/golang.org/x/oauth2/google"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/tools/go/gcimporter15/testdata"
	"context"
)

const (
	iamEntityType                string = "iam"
	gceEntityType                string = "gce"
	inferredProjectVal           string = "-"
	identityMetadataAttrTemplate string = "service-accounts/%s/identity?aud=%s&format=full"
)

type AuthCLIHandler struct{}

func getServiceAccountJWT(role string, m map[string]string) (string, error) {
	project, ok := m["project"]
	if !ok || len(project) == 0 {
		project = inferredProjectVal
	}

	serviceAccount, ok := m["service_account"]
	if !ok || serviceAccount == "" {
		return "", errors.New("service_account cannot be empty for 'iam'")
	}

	// Use credentials given or Application Default Credentials to create IAM client.
	credentialsJson, ok := m["credentials"]
	var creds *GcpCredentials
	if len(credentialsJson) > 0 {
		var err error
		creds, err = Credentials(credentialsJson)
		if err != nil {
			return "", err
		}
	}
	httpClient, err := HttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		return "", err
	}

	iamClient, err := iam.New(httpClient)
	if err != nil {
		return "", err
	}

	// Parse expires-in minutes from string.
	expInMinStr, ok := m["expires_in_min"]
	if len(expInMinStr) == 0 {
		expInMinStr = "15"
	}
	expInMin, err := strconv.ParseInt(expInMinStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("expected string representation of integer for expires_in_min, got %s", expInMin)
	}

	// Payload is the JSON Web Token claims we pass to projects.serviceAccounts.signJwt.
	payload := map[string]interface{}{
		"aud": fmt.Sprintf("vault/%s", role),
		"exp": time.Now().Add(time.Duration(-1*expInMin) * time.Minute),
		"sub": serviceAccount,
	}
	payloadStr, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signJwtResp, err := iamClient.Projects.ServiceAccounts.SignJwt(
		fmt.Sprintf("projects/%s/serviceAccounts/%s", project, serviceAccount),
		&iam.SignJwtRequest{
			Payload: string(payloadStr),
		}).Do()
	if err != nil {
		return "", nil
	}

	return signJwtResp.SignedJwt, nil
}

func getComputeInstanceMetadata(role string, m map[string]string) (string, error) {
	serviceAccount, ok := m["service_account"]
	if !ok || serviceAccount == "" {
		serviceAccount = "default"
	}

	audience := fmt.Sprintf("https://vault/%s", role)
	return metadata.Get(fmt.Sprintf(identityMetadataAttrTemplate, serviceAccount, audience))
}

func (h *AuthCLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "gcp"
	}

	role, ok := m["role"]
	if !ok || len(role) == 0 {
		return nil, errors.New("role cannot be empty")
	}

	entityType, ok := m["entity_type"]
	if !ok {
		entityType = ""
	}

	var token string
	var err error
	switch entityType {
	case iamEntityType:
		token, err = getServiceAccountJWT(role, m)
	case gceEntityType:
		token, err = getComputeInstanceMetadata(role, m)
	default:
		return nil, fmt.Errorf("unsupported entity_type %s", entityType)
	}

	if err != nil {
		return nil, err
	} else if len(token) > 0 {
		return nil, fmt.Errorf("empty response from Google for token of type %s", entityType)
	}

	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := c.Logical().Write(path, map[string]interface{}{
		"role": role,
		"jwt":  token,
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func (h *AuthCLIHandler) Help() string {
	help := `
The GCP credential provider allows you to authenticate to the GCP auth backend
using either an IAM service account or a Google Compute Engine VM instance.

The backend accepts respectively:
	iam: A JSON Web Token (JWT) signed using a service	account key
	gce: A instance identity metadata token (also a JWT) that is generated per instance and
		 accessed using the metadata server.

Example:
	vault auth -method=gcp entity_type=[iam | gce]

Accepted Arguments (Key/Value Pairs):
General:
	entity_type	Type of the entity. Accepted values: 'iam', 'gce'
	mount=gcp	The mountpoint for the GCP credential provider.
				Defaults to "gcp"
	role			Name of the Vault GCP auth backend role you are requesting an auth token.

Specific to entity_type='iam':
	project						Name of the GCP project the service account belongs to. If not provided,
								GCP will attempt to infer it from the service account.
	service_account 				The email/ID of the service account you are requesting a token for.
	credentials		 			You can specify valid GCP IAM credentials explicitly (not recommended).
								If not provided, this will use the Application Default Credentials.
								These must have the permission "iam.serviceAccounts.signJwt" on
								service_account.
	expires_in_min				An integer representing the minutes that the generated token will
								expire in. Defaults to 15 min, corresponding to the default
								allowed expiration for the GCP auth backend.

Specific to entity_type='gce':
	service_account 				The email of the service account you are requesting the instance
								metadata token under. Defaults to 'default'.
`
	return help
}
