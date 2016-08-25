// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package caddyKubernetesStorage

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"
	"strings"

	"github.com/mholt/caddy/caddytls"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sApiErrors "k8s.io/kubernetes/pkg/api/errors"
	k8sRest "k8s.io/kubernetes/pkg/client/restclient"
	k8s "k8s.io/kubernetes/pkg/client/unversioned"
)

// Keys and key prefixes for various things
const (
	keyPrefixDomain   = "caddy-domain-"
	keyPrefixUser     = "caddy-user-"
	keyGlobal         = "caddy-global"
	domainKeyMetadata = "metadata"
	domainKeyLock     = "lock"
	userKeyReg        = "reg"
	userKeyKey        = "key"
	globalKeyEmail    = "email"
)
const lockTimeOut = 2*time.Minute

func init() {
	caddytls.RegisterStorageProvider("kubernetes", func(caURL *url.URL) (caddytls.Storage, error) { return NewStorageAuto() })
}

// Storage represents a caddy kubernetes storage.
// Use one of NewStorageAuto, NewStorageInCluster or NewStorageWithConfig to initialize.
type Storage struct {
	c         *k8s.Client
	namespace string
}

// NewStorageAuto attempts to determine whether to call NewStorageWithConfig or NewStorageInCluster.
// It will call NewStorageWithConfig if the following env vars are declared: CADDY_K8S_CONF_PATH, CADDY_K8S_NAMESPACE
// Otherwise, it will call NewStorageInCluster.
func NewStorageAuto() (*Storage, error) {
	confPath := os.Getenv("CADDY_K8S_CONF_PATH")
	namespace := os.Getenv("CADDY_K8S_NAMESPACE")

	if namespace != "" && confPath != "" {
		f, err := os.Open(confPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		// Use a JSON decoder to decode the config from disk
		// The config has some Go specific stuff that the json decoder won't ever be able to fill in
		// But at least it does cover most of the fields
		conf := k8sRest.Config{}
		if err := json.NewDecoder(f).Decode(&conf); err != nil {
			return nil, err
		}

		return NewStorageWithConfig(namespace, &conf)
	}

	return NewStorageInCluster()
}

// NewStorageInCluster will initialize a new Storage.
// Login credentials will be taken from the kubernetes pod.
// If not in a cluster, use NewStorageWithConfig.
func NewStorageInCluster() (*Storage, error) {
	// Create a new inCluster config, this will automatically grab the serviceaccount info from /var/run/secrets/kubernetes.io/serviceaccount/
	c, err := k8s.NewInCluster()
	if err != nil {
		return nil, err
	}

	// Read /var/run/secrets/kubernetes.io/serviceaccount/namespace to find the current namespace
	namespace, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return nil, err
	}

	return &Storage{
		c:         c,
		namespace: string(namespace),
	}, nil
}

// NewStorageWithConfig will initialize a new storage based on the passed config and namespace.
func NewStorageWithConfig(namespace string, conf *k8sRest.Config) (*Storage, error) {
	c, err := k8s.New(conf)
	if err != nil {
		return nil, err
	}

	return &Storage{
		c:         c,
		namespace: namespace,
	}, nil
}

// SiteExists returns true if this site exists in storage.
// Site data is considered present when StoreSite has been called
// successfully (without DeleteSite having been called, of course).
func (k *Storage) SiteExists(domain string) (bool, error) {
	s, err := k.c.Secrets(k.namespace).Get(keyPrefixDomain + domain)
	if err == nil {
		_, okCert := s.Data[k8sApi.TLSCertKey]
		_, okKey := s.Data[k8sApi.TLSPrivateKeyKey]
		return okCert && okKey, nil
	} else if k8sApiErrors.IsNotFound(err) {
		return false, nil
	} else {
		return false, err
	}
}

// LoadSite obtains the site data from storage for the given domain and
// returns it. If data for the domain does not exist, the
// ErrStorageNotFound error instance is returned.
// care has been taken to make this load atomic to prevent
// race conditions that happen with multiple data loads.
func (k *Storage) LoadSite(domain string) (*caddytls.SiteData, error) {
	s, err := k.c.Secrets(k.namespace).Get(keyPrefixDomain + domain)
	if k8sApiErrors.IsNotFound(err) {
		return nil, caddytls.ErrStorageNotFound
	} else if err != nil {
		return nil, err
	}

	cert, certOk := s.Data[k8sApi.TLSCertKey]
	key, keyOk := s.Data[k8sApi.TLSPrivateKeyKey]

	if !certOk || !keyOk {
		return nil, caddytls.ErrStorageNotFound
	}

	return &caddytls.SiteData{
		Cert: cert,
		Key:  key,
		Meta: s.Data[domainKeyMetadata],
	}, nil
}

// StoreSite persists the given site data for the given domain in
// storage. Care has been taken to make this call atomic to prevent
// half-written data on failure of an internal intermediate storage
// step. this function should only be invoked after LockRegister
// and before UnlockRegister of the same domain.
func (k *Storage) StoreSite(domain string, data *caddytls.SiteData) error {
	// StoreSite assumes that we can safely Get and Update, this is because LockRegister takes care of creating the key if necessary
	// This keeps StoreSite simpler
	// Kubernetes uses a ResourceVersion on the secret to keep track of any concurrent changes and will error if there are any
	key := keyPrefixDomain + domain
	handle := k.c.Secrets(k.namespace)
	s, err := handle.Get(key)
	if k8sApiErrors.IsNotFound(err) {
		return fmt.Errorf("Secret key '%s' does not exist", key)
	} else if err != nil {
		return err
	}

	s.Data[k8sApi.TLSCertKey] = data.Cert
	s.Data[k8sApi.TLSPrivateKeyKey] = data.Key
	s.Data[domainKeyMetadata] = data.Meta

	_, err = handle.Update(s)
	return err
}

// DeleteSite deletes the site for the given domain from storage.
// If the site does not exist, the ErrStorageNotFound error instance is
// returned.
func (k *Storage) DeleteSite(domain string) error {
	err := k.c.Secrets(k.namespace).Delete(keyPrefixDomain + domain)
	if k8sApiErrors.IsNotFound(err) {
		return caddytls.ErrStorageNotFound
	}

	return err
}

// LockRegister should be called before the caller attempts to obtain or renew a
// certificate. This function is used as a mutex/semaphore for making
// sure something else isn't already attempting obtain/renew. It will
// return true (without error) if the lock is successfully obtained
// meaning nothing else is attempting renewal. It will return false
// (without error) if this domain is already locked by something else
// attempting renewal. To prevent deadlocks, the lock has a timeout of two minutes.
// Errors are only returned in exceptional cases.
func (k *Storage) LockRegister(domain string) (bool, error) {
	key := keyPrefixDomain + domain
	handle := k.c.Secrets(k.namespace)
	s, err := handle.Get(key)
	errIsNotFound := k8sApiErrors.IsNotFound(err)
	if err != nil && !errIsNotFound {
		return false, err
	}

	if errIsNotFound {
		t, err := time.Now().MarshalText()
		if err != nil {
			return false, err
		}

		// Handle creation
		_, err = handle.Create(&k8sApi.Secret{
			ObjectMeta: k8sApi.ObjectMeta{Name: key},
			Data:       map[string][]byte{domainKeyLock: []byte(t)},
			Type:       k8sApi.SecretTypeOpaque,
		})

		if err == nil {
			return true, nil
		}

		// It's entirely possible something else managed to create the entry while we weren't looking, check for that
		// if it isn't an already exists error, we just bail
		if !k8sApiErrors.IsAlreadyExists(err) {
			return false, err
		}

		// If it already exists, we continue with an update, but first we have to get the record
		handle.Get(key)
		s, err = handle.Get(key)

		// If we get an error of any kind, just bail, it's hopeless at this point
		if err != nil {
			return false, err
		}

		// We managed to get the record someone sneakily created behind our back, which means we can do an update now :)
	}

	// Handle update
	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	lockData, isLocked := s.Data[domainKeyLock]
	if isLocked {
		t := new(time.Time)
		if err := t.UnmarshalText(lockData); err != nil {
			return false, err
		}

		// Verify if the lock is still valid, if so, return false and no error ==> Already locked by something else
		if t.After(time.Now().Add(-lockTimeOut)) {
			return false, nil
		}

		// The lock expired, go on
	}

	// Generate fresh lockData
	lockData, err = time.Now().MarshalText()
	if err != nil {
		return false, err
	}

	s.Data[domainKeyLock] = lockData

	// Make sure to check if someone else nibbed the lock before we could, if so, we just return false and no error
	if _, err := handle.Update(s); k8sApiErrors.IsConflict(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

// UnlockRegister should be called after the caller has attempted to obtain or renew
// a certificate, regardless of whether it was successful. This will
// attempt to unlock the lock obtained in this process by LockRegister.
// If no lock exists, the implementation will not return an error.
// Errors are only returned in exceptional cases.
func (k *Storage) UnlockRegister(domain string) error {
	key := keyPrefixDomain + domain
	handle := k.c.Secrets(k.namespace)
	s, err := handle.Get(key)
	if k8sApiErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	delete(s.Data, domainKeyLock)
	_, err = handle.Update(s)
	return err
}

// LoadUser obtains user data from storage for the given email and
// returns it. If data for the email does not exist, the
// ErrStorageNotFound error instance is returned. Multi-server
// implementations should take care to make this operation atomic for
// all loaded data items.
func (k *Storage) LoadUser(email string) (*caddytls.UserData, error) {
	s, err := k.c.Secrets(k.namespace).Get(k.emailToKey(email))
	if k8sApiErrors.IsNotFound(err) {
		return nil, caddytls.ErrStorageNotFound
	} else if err != nil {
		return nil, err
	}

	return &caddytls.UserData{
		Reg: s.Data[userKeyReg],
		Key: s.Data[userKeyKey],
	}, nil
}

// StoreUser persists the given user data for the given email in
// storage. Care has been taken to make this operation atomic
// for all stored data items.
func (k *Storage) StoreUser(email string, data *caddytls.UserData) error {
	key := k.emailToKey(email)
	handle := k.c.Secrets(k.namespace)
	s, err := handle.Get(key)
	errIsNotFound := k8sApiErrors.IsNotFound(err)

	if err != nil && !errIsNotFound {
		return err
	}

	if errIsNotFound {
		// Handle creation
		_, err := handle.Create(&k8sApi.Secret{
			ObjectMeta: k8sApi.ObjectMeta{Name: key},
			Data: map[string][]byte{
				userKeyReg: data.Reg,
				userKeyKey: data.Key,
			},
			Type: k8sApi.SecretTypeOpaque,
		})

		if err != nil {
			return err
		}

		return k.storeRecentUserEmail(email)
	}

	// Handle update
	s.Data[userKeyReg] = data.Reg
	s.Data[userKeyKey] = data.Key
	_, err = handle.Update(s)

	if err != nil {
		return err
	}

	return k.storeRecentUserEmail(email)
}

func (k *Storage) emailToKey(email string) string {
	return keyPrefixUser + strings.ToLower(strings.TrimRight(base32.HexEncoding.EncodeToString([]byte(email)), "="))
}

func (k *Storage) storeRecentUserEmail(email string) error {
	handle := k.c.Secrets(k.namespace)
	s, err := handle.Get(keyGlobal)
	errIsNotFound := k8sApiErrors.IsNotFound(err)

	if err != nil && !errIsNotFound {
		return err
	}

	if errIsNotFound {
		// Handle creation
		_, err := handle.Create(&k8sApi.Secret{
			ObjectMeta: k8sApi.ObjectMeta{Name: keyGlobal},
			Data:       map[string][]byte{globalKeyEmail: []byte(email)},
			Type:       k8sApi.SecretTypeOpaque,
		})

		return err
	}

	// Handle update
	s.Data[globalKeyEmail] = []byte(email)
	_, err = handle.Update(s)
	return err
}

// MostRecentUserEmail provides the most recently used email parameter
// in StoreUser. The result is an empty string if there are no
// persisted users in storage.
func (k *Storage) MostRecentUserEmail() string {
	s, err := k.c.Secrets(k.namespace).Get(keyGlobal)

	if err != nil {
		return ""
	}

	return string(s.Data[globalKeyEmail])
}
