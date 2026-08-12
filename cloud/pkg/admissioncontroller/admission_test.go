/*
Copyright 2026 The KubeEdge Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package admissioncontroller

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubeedge/kubeedge/cloud/cmd/admission/app/options"
)

// registeredForCABundle returns a controller whose webhooks are registered for the CA
// certificate written to the options it returns.
func registeredForCABundle(t *testing.T, caBundle []byte) (*AdmissionController, *fake.Clientset, *options.AdmissionOptions) {
	t.Helper()

	opt := &options.AdmissionOptions{
		CaCertFile:                filepath.Join(t.TempDir(), "ca.crt"),
		Port:                      443,
		AdmissionServiceNamespace: "kubeedge",
		AdmissionServiceName:      "kubeedge-admission-service",
	}
	require.NoError(t, os.WriteFile(opt.CaCertFile, caBundle, 0600))

	clientset := fake.NewSimpleClientset()
	ac := &AdmissionController{Client: clientset}
	require.NoError(t, ac.registerWebhooks(opt, caBundle))
	return ac, clientset, opt
}

// publishedCABundle returns the CA bundle the validating webhook configuration holds.
func publishedCABundle(clientset *fake.Clientset) ([]byte, error) {
	configuration, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(context.Background(), ValidateCRDWebhookConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return configuration.Webhooks[0].ClientConfig.CABundle, nil
}

func TestRefreshCABundle(t *testing.T) {
	oldCA := []byte("old ca certificate")
	newCA := []byte("rotated ca certificate")

	ac, clientset, opt := registeredForCABundle(t, oldCA)

	t.Run("unchanged ca is not published again", func(t *testing.T) {
		clientset.ClearActions()

		assert.Equal(t, oldCA, ac.refreshCABundle(opt, oldCA))
		assert.Empty(t, clientset.Actions())
	})

	t.Run("rotated ca is published", func(t *testing.T) {
		require.NoError(t, os.WriteFile(opt.CaCertFile, newCA, 0600))

		assert.Equal(t, newCA, ac.refreshCABundle(opt, oldCA))
		published, err := publishedCABundle(clientset)
		assert.NoError(t, err)
		assert.Equal(t, newCA, published)
	})

	t.Run("rejected registration keeps the published bundle", func(t *testing.T) {
		require.NoError(t, os.WriteFile(opt.CaCertFile, []byte("ca certificate rotated again"), 0600))
		clientset.PrependReactor("update", "validatingwebhookconfigurations",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewInternalError(errors.New("registration failed"))
			})

		assert.Equal(t, newCA, ac.refreshCABundle(opt, newCA))
		published, err := publishedCABundle(clientset)
		assert.NoError(t, err)
		assert.Equal(t, newCA, published)
	})

	t.Run("unreadable ca keeps the published bundle", func(t *testing.T) {
		require.NoError(t, os.Remove(opt.CaCertFile))

		assert.Equal(t, newCA, ac.refreshCABundle(opt, newCA))
		published, err := publishedCABundle(clientset)
		assert.NoError(t, err)
		assert.Equal(t, newCA, published)
	})
}

func TestWatchCABundle(t *testing.T) {
	oldCA := []byte("old ca certificate")
	newCA := []byte("rotated ca certificate")

	ac, clientset, opt := registeredForCABundle(t, oldCA)
	// Rotate the CA before the watch starts, its first pass has to publish it.
	require.NoError(t, os.WriteFile(opt.CaCertFile, newCA, 0600))

	stopCh, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ac.watchCABundle(opt, oldCA, stopCh)
	}()
	defer func() {
		close(stopCh)
		<-stopped
	}()

	assert.Eventually(t, func() bool {
		published, err := publishedCABundle(clientset)
		return err == nil && bytes.Equal(published, newCA)
	}, 10*time.Second, 10*time.Millisecond)
}

func TestConfigTLS(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	writeKeyPair(t, certFile, keyFile, "kubeedge-admission-service.kubeedge.svc")

	certPEM, err := os.ReadFile(certFile)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	t.Run("key pair from the given files", func(t *testing.T) {
		assert := assert.New(t)

		tlsConfig, err := configTLS(&options.AdmissionOptions{CertFile: certFile, KeyFile: keyFile}, &restclient.Config{})
		assert.NoError(err)
		assert.Equal(uint16(tls.VersionTLS12), tlsConfig.MinVersion)
		assert.Equal("kubeedge-admission-service.kubeedge.svc", servedCommonName(t, tlsConfig.GetCertificate))
	})

	t.Run("unreadable key pair", func(t *testing.T) {
		opt := &options.AdmissionOptions{
			CertFile: filepath.Join(dir, "missing.crt"),
			KeyFile:  filepath.Join(dir, "missing.key"),
		}

		_, err := configTLS(opt, &restclient.Config{})
		assert.Error(t, err)
	})

	t.Run("key pair from the kubeconfig", func(t *testing.T) {
		assert := assert.New(t)

		restConfig := &restclient.Config{
			TLSClientConfig: restclient.TLSClientConfig{CertData: certPEM, KeyData: keyPEM},
		}

		tlsConfig, err := configTLS(&options.AdmissionOptions{}, restConfig)
		assert.NoError(err)
		assert.Len(tlsConfig.Certificates, 1)
	})

	t.Run("no key pair at all", func(t *testing.T) {
		_, err := configTLS(&options.AdmissionOptions{}, &restclient.Config{})
		assert.Error(t, err)
	})
}
