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

package org.eclipse.tractusx.wallet.stub.storage.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;

@Entity
public class HolderCredentialStore {

    @Id
    private String key;

    @Lob
    private CustomCredential customCredential;

    public HolderCredentialStore(String key, CustomCredential customCredential) {
        this.customCredential = customCredential;
        this.key = key;
    }

    public CustomCredential getCustomCredential() {
        return customCredential;
    }

    public void setCustomCredential(CustomCredential customCredential) {
        this.customCredential = customCredential;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
