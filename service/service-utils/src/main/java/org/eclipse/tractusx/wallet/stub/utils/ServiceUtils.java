/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
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

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.keycloak.admin.client.token.TokenService;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ServiceUtils {

    private final Storage storage;

    private final WalletStubSettings walletStubSettings;

    /**
     * Retrieves a KeyPair associated with the provided business partner number (bpn).
     *
     * @param bpn the business partner number
     * @return the KeyPair associated with the provided bpn, or generates a new KeyPair and saves it if no KeyPair is found
     */
    public KeyPair getKeyPair(String bpn) {
        Optional<KeyPair> optionalKeyPair = storage.getKeyPair(bpn);
        return optionalKeyPair.orElseGet(() -> {
            KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair(bpn, walletStubSettings.env());
            storage.saveKeyPair(bpn, keyPair);
            return keyPair;
        });
    }

    @SneakyThrows
    private boolean verifyToken(String token) {
        SignedJWT signedJWT = SignedJWT.parse(CommonUtils.cleanToken(token));
        String keyID = signedJWT.getHeader().getKeyID(); //this will be DID
        String bpn = CommonUtils.getBpnFromDid(keyID);
        KeyPair keyPair = this.getKeyPair(bpn);
        ECPublicKey aPublic = (ECPublicKey) keyPair.getPublic();
        ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(aPublic);
        ecdsaVerifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        return signedJWT.verify(ecdsaVerifier);
    }

    @SneakyThrows
    public JWTClaimsSet verifyTokenAndGetClaims(String token) {
        if (this.verifyToken(token)) {
            return SignedJWT.parse(CommonUtils.cleanToken(token)).getJWTClaimsSet();
        } else {
            throw new IllegalArgumentException("Invalid token: " + token);
        }
    }

    /**
     * Retrieves the business partner number (BPN) from a JWT (JSON Web Token) using the provided token and token service.
     *
     * @param token        The JWT token containing the BPN.
     * @return The business partner number (BPN) extracted from the JWT.
     */
    @SneakyThrows
    public String getBpnFromToken(String token) {
        SignedJWT signedJWT = SignedJWT.parse(CommonUtils.cleanToken(token));
        JWTClaimsSet jwtClaimsSet = this.verifyTokenAndGetClaims(signedJWT.serialize());
        return jwtClaimsSet.getClaim(StringPool.BPN).toString();
    }


    /**
     * Retrieves the audience from a JWT (JSON Web Token) using the provided token and token service.
     *
     * @param token        The JWT token containing the BPN.
     * @return The audience extracted from the JWT.
     */
    @SneakyThrows
    public String getAudienceFromToken(String token) {
        SignedJWT signedJWT = SignedJWT.parse(CommonUtils.cleanToken(token));
        JWTClaimsSet jwtClaimsSet = this.verifyTokenAndGetClaims(signedJWT.serialize());
        List<String> audienceList = jwtClaimsSet.getAudience();
        if (audienceList != null && !audienceList.isEmpty()) {
            return audienceList.get(0);
        } else {
            throw new IllegalArgumentException("Audience not found in the token");
        }
    }
}
