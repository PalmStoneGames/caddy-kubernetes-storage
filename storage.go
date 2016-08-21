// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package caddy_k8s_storage

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/mholt/caddy/caddytls"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sApiErrors "k8s.io/kubernetes/pkg/api/errors"
	k8s "k8s.io/kubernetes/pkg/client/unversioned"
	"net/url"
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
const lockTimeOut = time.Minute

func init() {
	caddytls.RegisterStorageProvider("kubernetes", func(caURL *url.URL) (caddytls.Storage, error) { return NewKubernetesStorage() })
}

type KubernetesStorage struct {
	c         *k8s.Client
	namespace string
}

func NewKubernetesStorage() (*KubernetesStorage, error) {
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

	return &KubernetesStorage{
		c:         c,
		namespace: string(namespace),
	}, nil
}

// SiteExists returns true if this site exists in storage.
// Site data is considered present when StoreSite has been called
// successfully (without DeleteSite having been called, of course).
func (k *KubernetesStorage) SiteExists(domain string) (bool, error) {
	_, err := k.c.Secrets(k.namespace).Get(keyPrefixDomain + domain)
	if err == nil {
		return true, nil
	} else if k8sApiErrors.IsNotFound(err) {
		return false, nil
	} else {
		return false, err
	}
}

// LoadSite obtains the site data from storage for the given domain and
// returns it. If data for the domain does not exist, the
// ErrStorageNotFound error instance is returned. For multi-server
// storage, care should be taken to make this load atomic to prevent
// race conditions that happen with multiple data loads.
func (k *KubernetesStorage) LoadSite(domain string) (*caddytls.SiteData, error) {
	s, err := k.c.Secrets(k.namespace).Get(keyPrefixDomain + domain)
	if k8sApiErrors.IsNotFound(err) {
		return nil, caddytls.ErrStorageNotFound
	} else if err != nil {
		return nil, err
	}

	return &caddytls.SiteData{
		Cert: s.Data[k8sApi.TLSCertKey],
		Key:  s.Data[k8sApi.TLSPrivateKeyKey],
		Meta: s.Data[domainKeyMetadata],
	}, nil
}

// StoreSite persists the given site data for the given domain in
// storage. For multi-server storage, care should be taken to make this
// call atomic to prevent half-written data on failure of an internal
// intermediate storage step. Implementers can trust that at runtime
// this function will only be invoked after LockRegister and before
// UnlockRegister of the same domain.
func (k *KubernetesStorage) StoreSite(domain string, data *caddytls.SiteData) error {
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
// Multi-server implementations should attempt to make this atomic. If
// the site does not exist, the ErrStorageNotFound error instance is
// returned.
func (k *KubernetesStorage) DeleteSite(domain string) error {
	err := k.c.Secrets(k.namespace).Delete(keyPrefixDomain + domain)
	if k8sApiErrors.IsNotFound(err) {
		return caddytls.ErrStorageNotFound
	} else {
		return err
	}
}

// LockRegister is called before Caddy attempts to obtain or renew a
// certificate. This function is used as a mutex/semaphore for making
// sure something else isn't already attempting obtain/renew. It should
// return true (without error) if the lock is successfully obtained
// meaning nothing else is attempting renewal. It should return false
// (without error) if this domain is already locked by something else
// attempting renewal. As a general rule, if this isn't multi-server
// shared storage, this should always return true. To prevent deadlocks
// for multi-server storage, all internal implementations should put a
// reasonable expiration on this lock in case UnlockRegister is unable to
// be called due to system crash. Errors should only be returned in
// exceptional cases. Any error will prevent renewal.
func (k *KubernetesStorage) LockRegister(domain string) (bool, error) {
	key := keyPrefixDomain + domain
	handle := k.c.Secrets(k.namespace)
	s, err := handle.Get(key)
	errIsNotFound := k8sApiErrors.IsNotFound(err)
	if err != nil && !errIsNotFound {
		return false, err
	}

	if errIsNotFound {
		// Handle creation
		_, err := handle.Create(&k8sApi.Secret{
			ObjectMeta: k8sApi.ObjectMeta{Name: key},
			Data:       map[string][]byte{domainKeyLock: []byte(time.Now().String())},
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

// UnlockRegister is called after Caddy has attempted to obtain or renew
// a certificate, regardless of whether it was successful. If
// LockRegister essentially just returns true because this is not
// multi-server storage, this can be a no-op. Otherwise this should
// attempt to unlock the lock obtained in this process by LockRegister.
// If no lock exists, the implementation should not return an error. An
// error is only for exceptional cases.
func (k *KubernetesStorage) UnlockRegister(domain string) error {
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
func (k *KubernetesStorage) LoadUser(email string) (*caddytls.UserData, error) {
	s, err := k.c.Secrets(k.namespace).Get(keyPrefixUser + base64.URLEncoding.EncodeToString([]byte(email)))
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
// storage. Multi-server implementations should take care to make this
// operation atomic for all stored data items.
func (k *KubernetesStorage) StoreUser(email string, data *caddytls.UserData) error {
	key := keyPrefixUser + base64.URLEncoding.EncodeToString([]byte(email))
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

func (k *KubernetesStorage) storeRecentUserEmail(email string) error {
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
func (k *KubernetesStorage) MostRecentUserEmail() string {
	s, err := k.c.Secrets(k.namespace).Get(keyGlobal)

	if err != nil {
		return ""
	}

	return string(s.Data[globalKeyEmail])
}