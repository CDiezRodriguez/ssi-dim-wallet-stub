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

import org.springframework.stereotype.Service;

import java.util.List;

@Service
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

    public Boolean validateCompanyAndConnector(String bpn, String url){
        CompanyDTO company = companyRepository.getCompany(bpn);
        if (company == null){
            return false;
        }
        ConnectorDTO connector = connectorRepository.getConnector(url, company.getId());
        return connector != null;
    }
}
