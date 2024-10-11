/*
 * *******************************************************************************
 *  Copyright (c) 2024 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.wallet.stub.storage;

import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.storage.entity.CredentialStore;
import org.eclipse.tractusx.wallet.stub.storage.entity.DidDocumentStore;
import org.eclipse.tractusx.wallet.stub.storage.entity.HolderCredentialAsJWTStore;
import org.eclipse.tractusx.wallet.stub.storage.entity.HolderCredentialStore;
import org.eclipse.tractusx.wallet.stub.storage.entity.JWTCredentialStore;
import org.eclipse.tractusx.wallet.stub.storage.entity.KeyStore;
import org.eclipse.tractusx.wallet.stub.storage.repository.CredentialStoreRepository;
import org.eclipse.tractusx.wallet.stub.storage.repository.DidDocumentStoreRepository;
import org.eclipse.tractusx.wallet.stub.storage.repository.HolderCredentialAsJwtStoreRepository;
import org.eclipse.tractusx.wallet.stub.storage.repository.HolderCredentialStoreRepository;
import org.eclipse.tractusx.wallet.stub.storage.repository.JwtCredentialStoreRepository;
import org.eclipse.tractusx.wallet.stub.storage.repository.KeyStoreRepository;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Optional;

@Service
public class DBSorage implements Storage{

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    @Autowired
    private DidDocumentStoreRepository didDocumentStoreRepository;

    @Autowired
    private CredentialStoreRepository credentialStoreRepository;

    @Autowired
    private JwtCredentialStoreRepository jwtCredentialStoreRepository;

    @Autowired
    private HolderCredentialStoreRepository holderCredentialStoreRepository;

    @Autowired
    private HolderCredentialAsJwtStoreRepository holderCredentialAsJwtStoreRepository;

    @Override
    public void saveCredentialAsJwt(String vcId, String jwt, String holderBPn, String type) {
        String key = Storage.getMapKey(holderBPn, type);
        holderCredentialAsJwtStoreRepository.save(new HolderCredentialAsJWTStore(key, jwt));
        jwtCredentialStoreRepository.findById(vcId).orElseGet(() -> jwtCredentialStoreRepository.save(new JWTCredentialStore(vcId,jwt)));
    }

    @Override
    public Optional<String> getCredentialAsJwt(String vcId) {
        return Optional.ofNullable(jwtCredentialStoreRepository.findById(vcId).get().getJwt());
    }

    @Override
    public void saveCredentials(String vcId, CustomCredential credential, String holderBpn, String type) {
        String key = Storage.getMapKey(holderBpn, type);
        holderCredentialStoreRepository.save(new HolderCredentialStore(key,credential));
        credentialStoreRepository.findById(vcId).orElseGet(() -> credentialStoreRepository.save(new CredentialStore(vcId, credential)));
    }

    @Override
    public Optional<CustomCredential> getCredentialsByHolderBpnAndType(String holderBpn, String type) {
        return Optional.ofNullable(holderCredentialStoreRepository.findById(Storage.getMapKey(holderBpn,type)).get().getCustomCredential());
    }

    @Override
    public Optional<String> getCredentialsAsJwtByHolderBpnAndType(String holderBpn, String type) {
        return Optional.ofNullable(holderCredentialAsJwtStoreRepository.findById(Storage.getMapKey(holderBpn,type)).get().getJwt());
    }

    @Override
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        return Optional.ofNullable(credentialStoreRepository.findById(vcId).get().getCustomCredential());
    }

    @Override
    public void saveKeyPair(String bpn, KeyPair keyPair) {
        keyStoreRepository.save(new KeyStore(bpn, keyPair.getPrivate(), keyPair.getPublic()));
    }

    @Override
    public void saveDidDocument(String bpn, DidDocument didDocument) {
        didDocumentStoreRepository.save(new DidDocumentStore(bpn, didDocument));
    }

    @Override
    public Optional<KeyPair> getKeyPair(String bpn) {
        Optional<KeyStore> keyStore = keyStoreRepository.findById(bpn);
        if (keyStore.isPresent())
        {
            KeyPair keyPair = new KeyPair(keyStore.get().getPublickKey(), keyStore.get().getPrivateKey());
            return Optional.of(keyPair);
        }
        return Optional.empty();
    }

    @Override
    public Optional<DidDocument> getDidDocument(String bpn) {
        Optional<DidDocumentStore> didDocumentStore = didDocumentStoreRepository.findById(bpn);
        if (didDocumentStore.isPresent())
        {
            return Optional.of(didDocumentStore.get().getDidDocumet());
        }
        return Optional.empty();
    }
}
