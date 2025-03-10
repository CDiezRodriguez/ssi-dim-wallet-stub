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

package org.eclipse.tractusx.wallet.stub.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.utils.ServiceUtils;
import org.eclipse.tractusx.wallet.stub.token.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Date;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService {

    private final DidDocumentService didDocumentService;

    private final TokenSettings tokenSettings;

    private final ServiceUtils serviceUtils;


    /**
     * Creates an access token response for the given client ID.
     *
     * @param request The token request containing the client ID.
     * @return A {@link TokenResponse} object containing the access token, token type, and expiration time.
     */
    @SneakyThrows
    public TokenResponse createAccessTokenResponse(TokenRequest request) {

        //here clientId will be BPN
        KeyPair keyPair = serviceUtils.getKeyPair(request.getClientId());
        DidDocument didDocument = didDocumentService.getDidDocument(request.getClientId());

        //time config
        Date time = new Date();
        Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

        //claims
        JWTClaimsSet body = new JWTClaimsSet.Builder()
                .issueTime(time)
                .jwtID(UUID.randomUUID().toString())
                .audience(didDocument.getId())
                .expirationTime(expiryTime)
                .claim(StringPool.BPN, request.getClientId())
                .issuer(didDocument.getId())
                .notBeforeTime(time)
                .subject(didDocument.getId())
                .build();

        SignedJWT signedJWT = CommonUtils.signedJWT(body, keyPair, didDocument.getVerificationMethod().getFirst().getId());

        String token = signedJWT.serialize();
        log.debug("Token created for client id -> {}  token -> {}", StringEscapeUtils.escapeJava(request.getClientId()), token);
        return new TokenResponse(token, StringPool.TOKEN_TYPE_BEARER, tokenSettings.tokenExpiryTime() * 60L, 0, 0, "email profile");
    }
}
