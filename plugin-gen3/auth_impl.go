package main

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/plugins/shared"
	"github.com/uc-cdis/go-authutils/authutils"

	"github.com/hashicorp/go-plugin"
	"github.com/ohsu-comp-bio/funnel/tes"
)

type Authorize struct{}

type StorageInfoResponse struct {
	Bucket    string `json:"bucket"`
	Region    string `json:"region"`
	KmsKeyArn string `json:"kms_key_arn"`
}

func validateTokenAndExtractUserId(token string) (string, error) {
	// This function was copied and adapted from arborist
	// https://github.com/uc-cdis/arborist/blob/2025.05/arborist/token.go#L16

	missingRequiredField := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: missing required field `%s`",
			field,
		)
		return errors.New(msg)
	}
	fieldTypeError := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: field `%s` has wrong type",
			field,
		)
		return errors.New(msg)
	}

	jwtApp := authutils.NewJWTApplication("http://fence-service/.well-known/jwks")
	claims, err := jwtApp.Decode(token)
	if err != nil {
		return "", fmt.Errorf("error decoding token: %w", err)
	}
	scopes := []string{"openid"}
	expected := &authutils.Expected{Scopes: scopes}

	err = expected.Validate(claims)
	if err != nil {
		return "", fmt.Errorf("error decoding token: %w", err)
	}
	userIdInterface, exists := (*claims)["sub"]
	if !exists {
		return "", missingRequiredField("sub")
	}
	userId, casted := userIdInterface.(string)
	if !casted {
		return "", fieldTypeError("sub")
	}

	return userId, nil
}

func errorResponse(code int64, msg string) (*proto.JobResponse, error) {
	// returning `nil` instead of the actual error here, because this response is parsed upstream
	// and a 500 is returned if the error is anything else than `nil`. The actual error code is
	// parsed from `JobResponse.code` instead.
	return &proto.JobResponse{
			Code:    code,
			Message: msg,
		},
		nil
}

func (a Authorize) PluginAction(params map[string]string, headers map[string]*proto.StringList, configuration *config.Config, task *tes.Task, taskType proto.Type) (*proto.JobResponse, error) {
	// only proceed for task creation events. The worker config does not need to be updated for
	// other types of events
	if taskType == proto.Type_GET || taskType == proto.Type_CANCEL {
		return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
	}
	if taskType != proto.Type_CREATE {
		return errorResponse(http.StatusBadRequest, fmt.Sprintf("unsupported task type: %v", taskType))
	}

	// get the plugin configuration
	S3Url, ok := params["S3Url"]
	if !ok || S3Url == "" {
		return errorResponse(http.StatusBadRequest, "S3Url is required in params")
	}
	shared.Logger.Info("Configuration", "S3Url", S3Url)

	// get the user's access token from the headers
	authHeaders, ok := headers["authorization"]
	if !ok || authHeaders == nil || len(authHeaders.Values) == 0 {
		return errorResponse(http.StatusBadRequest, "Authorization header is required")
	}
	authHeader := authHeaders.Values[0]
	if authHeader == "" {
		return errorResponse(http.StatusBadRequest, "Authorization header is required")
	}

	// validate the user's token and extract the user ID
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")
	_, err := validateTokenAndExtractUserId(userJWT)
	if err != nil {
		return errorResponse(http.StatusUnauthorized, fmt.Sprintf("unable to parse token: %v", err))
	}

	// get the S3 bucket and region for this user
	httpClient := &http.Client{Timeout: 10 * time.Second}
	url := "http://gen3-workflow-service/storage/setup"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("error creating HTTP request to '%s': %v", url, err))
	}
	req.Header.Add("Authorization", "bearer "+userJWT)
	resp, err := httpClient.Do(req)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("error making HTTP request to '%s': %v", url, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errorResponse(int64(resp.StatusCode), fmt.Sprintf("http error from '%s': status code %d, body: %s", url, resp.StatusCode, string(body)))
	}
	storageInfoResponse := new(StorageInfoResponse)
	err = json.NewDecoder(resp.Body).Decode(storageInfoResponse)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("could not parse '%s' response body: %v", url, err))
	}
	shared.Logger.Info("User's storage", "Bucket", storageInfoResponse.Bucket, "Region", storageInfoResponse.Region)

	// generate and return the worker configuration
	configuration.AmazonS3.Disabled = true
	configuration.GenericS3 = []*config.GenericS3Storage{
		{
			Disabled: false,
			Endpoint: S3Url,
			// Gen3's S3 gateway validates the SigV4 access-key ID as the
			// user's access token. Client tokens with a userId suffix are rejected.
			Key:      userJWT,
			Secret:   "N/A",
			Bucket:   storageInfoResponse.Bucket,
			Region:   storageInfoResponse.Region,
			KmsKeyID: storageInfoResponse.KmsKeyArn,
		},
	}
	return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
}

func main() {
	log.Println("Server: registering gob types")
	gob.Register(&config.TimeoutConfig_Duration{})
	gob.Register(&config.TimeoutConfig_Disabled{})

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"authorize": &shared.AuthorizePlugin{Impl: &Authorize{}},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
