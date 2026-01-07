package oidc

// Copyright 2024 Woodpecker Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func SetupRoutes() (http.Handler, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	jwks := goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{{
			KeyID:     "key_id",
			Key:       key,
			Algorithm: "RS256",
		}},
	}
	op, err := provider.New(
		goidc.ProfileOpenID,
		"http://localhost",
		func(_ context.Context) (goidc.JSONWebKeySet, error) {
			return jwks, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return op.Handler(), nil
}
