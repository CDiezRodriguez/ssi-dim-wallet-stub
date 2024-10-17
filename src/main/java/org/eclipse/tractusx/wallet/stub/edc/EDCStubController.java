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

package org.eclipse.tractusx.wallet.stub.edc;


import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.protocol.HTTP;
import org.eclipse.tractusx.wallet.stub.apidoc.EDCStubApiDoc;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.edc.dto.StsTokeResponse;
import org.eclipse.tractusx.wallet.stub.edc.portal.CompanyDTO;
import org.eclipse.tractusx.wallet.stub.edc.portal.ConnectorDTO;
import org.eclipse.tractusx.wallet.stub.edc.portal.PortalValidationService;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
@Tag(name = "APIs consumed by EDC")
public class EDCStubController {

    private final EDCStubService edcStubService;

    @Autowired
    private PortalValidationService portalValidationService;



    /**
     * Validate participants2
     * @param bpn   The bpn
     * @param connector_url The connector URL
     */

    @GetMapping(path = "/api/validate")
    public ResponseEntity<Boolean> validate(@RequestParam String bpn, @RequestParam String connector_url) throws UnknownHostException, MalformedURLException {
        return ResponseEntity.ok(portalValidationService.validateCompanyAndConnector(bpn,connector_url));
    }


    @GetMapping("/api/some-endpoint")
    public void getOrigin(HttpServletRequest request) throws UnknownHostException {

        System.out.println(request.getRemoteAddr()); //ESTE FUNCIONA
        System.out.println(request.getRemoteHost()); //ESTE FUNCIONA
        System.out.println(request.getRemotePort());
        System.out.println(request.getRemoteUser());

        System.out.println(InetAddress.getByName("dataconsumer-1-controlplane.tx.test").getHostAddress());
        System.out.println(InetAddress.getByName("192.168.49.2").getHostAddress());
    }

    /**
     * Validate participants
     */
    @EDCStubApiDoc.GetSts
    @PostMapping(path = "/api/validate/companies")
    public List<CompanyDTO> validate1() {
        return portalValidationService.getAllCompanies();
    }

    /**
     * Validate participants
     */
    @EDCStubApiDoc.GetSts
    @PostMapping(path = "/api/validate/connector")
    public List<ConnectorDTO> validate2() {
        return portalValidationService.getAllConnector();
    }

    /**
     * This method is responsible for creating a JWT token with a specific scope.
     *
     * @param request The request object containing the necessary data to create the token.
     * @param token   The authorization token provided in the request header.
     * @return A ResponseEntity containing a map with a single key-value pair: "jwt" and the generated JWT token.
     */
    @EDCStubApiDoc.GetSts
    @PostMapping(path = "/api/sts", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<StsTokeResponse> createTokenWithScope(
            @RequestBody Map<String, Object> request,
            @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token,
            HttpServletRequest Srequest
    ) {
        if (edcStubService.ValidateConnectorAndCompany(request,Srequest)){
            return ResponseEntity.ok(StsTokeResponse.builder().jwt(edcStubService.createStsToken(request, token)).build());
        }else{
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No companyBPNL or connectorURL register in Portal");
        }

    }


    /**
     * This method is responsible for querying presentations based on the provided request.
     *
     * @param request The request object containing the necessary data for querying presentations.
     * @param token   The authorization token provided in the request header.
     * @return A ResponseEntity containing the QueryPresentationResponse object with the query results.
     */
    @EDCStubApiDoc.QueryPresentation
    @PostMapping(path = "/api/presentations/query")
    public ResponseEntity<QueryPresentationResponse> queryPresentations(
            @RequestBody QueryPresentationRequest request,
            @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token
    ) {
        return ResponseEntity.ok(edcStubService.queryPresentations(request, token));
    }
}
