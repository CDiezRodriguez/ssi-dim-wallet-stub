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

package org.eclipse.tractusx.wallet.stub.edc.portal;

import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.buf.UEncoder;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.List;

@Service
@Slf4j
public class PortalValidationService {
    private final CompanyRepository companyRepository;
    private final ConnectorRepository connectorRepository;

    public PortalValidationService(CompanyRepository companyRepository, ConnectorRepository connectorRepository){
        this.companyRepository = companyRepository;
        this.connectorRepository = connectorRepository;
    }

    public List<CompanyDTO> getAllCompanies(){
        return companyRepository.getAllCompanies();
    }

    public List<ConnectorDTO> getAllConnector(){
        return connectorRepository.getAllConnectors();
    }

    public Boolean validateCompanyAndConnector(String bpn, String url) throws UnknownHostException, MalformedURLException {
        CompanyDTO company = companyRepository.getCompany(bpn);
        if (company == null){
            return false;
        }
        ConnectorDTO connector = connectorRepository.getConnector(url, company.getId());
        URL urlObtenido = new URL(connector.getConnector_url());
        String hostObtenido = InetAddress.getByName(urlObtenido.getHost()).getHostAddress();
        String hostAComparar = InetAddress.getByName(url).getHostAddress();
        log.debug("Compare introduced address -> {} with database ones ->{}", hostObtenido, hostAComparar);
        return hostObtenido.equals(hostAComparar);
    }
}
