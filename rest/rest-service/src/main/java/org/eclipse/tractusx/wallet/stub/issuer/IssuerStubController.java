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

package org.eclipse.tractusx.wallet.stub.issuer;

import io.swagger.v3.oas.annotations.Parameter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.Validate;
import org.eclipse.tractusx.wallet.stub.issuer.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.dto.SignCredentialResponse;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.Constants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The type Wallet controller.
 */
@RestController
@RequiredArgsConstructor
public class IssuerStubController implements IssuerStubApi{

    private final IssuerCredentialService issuerCredentialService;

    private final TokenService tokenService;

    public ResponseEntity<IssueCredentialResponse> createCredential(@RequestBody IssueCredentialRequest request,
                                                                    @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token) {
        Validate.isTrue(request.isValid(), "Invalid request");

        String vcId;
        String jwt = null;
        if (Objects.nonNull(request.getCredentialPayload().getDerive())) {
            vcId = issuerCredentialService.storeCredential(request, CommonUtils.getBpnFromToken(token, tokenService));
        } else {
            Map<String, String> map = issuerCredentialService.issueCredential(request, CommonUtils.getBpnFromToken(token, tokenService));
            vcId = map.get(Constants.ID);
            jwt = map.get(Constants.JWT);
        }
        IssueCredentialResponse response = IssueCredentialResponse.builder()
                .id(vcId)
                .jwt(jwt)
                .build();
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    public ResponseEntity<SignCredentialResponse> signOrRevokeCredential(@RequestBody SignCredentialRequest request, @PathVariable String credentialId) {
        if (Objects.nonNull(request.getPayload()) && request.getPayload().isRevoke()) {
            return ResponseEntity.ok(null);
        } else {
            Optional<String> jwtVc = issuerCredentialService.signCredential(credentialId);
            if (jwtVc.isPresent()) {
                return ResponseEntity.ok(new SignCredentialResponse(jwtVc.get()));
            } else {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No credential found for credentialId -> " + credentialId);
            }
        }
    }

    public GetCredentialsResponse getCredential(@PathVariable String externalCredentialId) {
        return issuerCredentialService.getCredential(externalCredentialId);
    }
}
