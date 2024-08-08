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

package org.eclipse.tractusx.wallet.stub.utils;

import lombok.experimental.UtilityClass;

@UtilityClass
public class StringPool {

    public static final String BPN = "bpn";
    public static final String TOKEN_TYPE_BEARER = "Bearer";
    public static final String TOKEN = "token";
    public static final String HOLDER_IDENTIFIER = "holderIdentifier";
    public static final String BASIC = "Basic";
    public static final String MEMBERSHIP_CREDENTIAL = "MembershipCredential";
    public static final String BPN_CREDENTIAL = "BpnCredential";
    public static final String STATUS_LIST_2021_CREDENTIAL = "StatusList2021Credential";
    public static final String ENCODED_LIST = "encodedList";
    public static final String VERIFIABLE_CREDENTIAL_CAMEL_CASE = "verifiableCredential";
    public static final String NONCE = "nonce";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String VP = "vp";
    public static final String VC = "vc";
    public static final String ID = "id";
    public static final String PRESENTATION_RESPONSE_MESSAGE = "PresentationResponseMessage";
    public static final String TYPE = "type";
    public static final String SCOPE = "scope";
    public static final String CREDENTIAL_SERVICE = "CredentialService";
    public static final String JSON_WEB_KEY_2020 = "JsonWebKey2020";
    public static final String STATUS_PURPOSE = "statusPurpose";
    public static final String REVOCATION = "revocation";
    public static final String HASH_SEPARATOR = "#";
    public static final String SIGN_TOKEN = "signToken";
    public static final String GRANT_ACCESS = "grantAccess";
    public static final String CONTEXT = "@context";
    public static final String CREDENTIAL_TYPES = "credentialTypes";
    public static final String BPN_NUMBER_REGEX = "^(BPN)(L|S|A)[0-9A-Z]{12}";
    public static final String BPN_REGEX = "BPN\\w+";
}
