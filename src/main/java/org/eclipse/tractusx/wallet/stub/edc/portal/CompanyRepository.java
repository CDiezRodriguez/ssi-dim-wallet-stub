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

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CompanyRepository {
    private final JdbcTemplate jdbcTemplate;

    public CompanyRepository(JdbcTemplate jdbcTemplate){
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<CompanyDTO> getAllCompanies(){
        String sql = "SELECT id,business_partner_number FROM portal.companies";
        return jdbcTemplate.query(sql, (rs, rowNum) ->
                new CompanyDTO(
                        rs.getString("id"),
                        rs.getString("business_partner_number")
                ));
    }

    public CompanyDTO getCompany(String business_partner_number){
        String sql = "SELECT id,business_partner_number FROM portal.companies WHERE business_partner_number = ?";

        try {
            return jdbcTemplate.queryForObject(sql, new Object[]{ business_partner_number }, (rs, rowNum) ->
                    new CompanyDTO(
                            rs.getString("id"),
                            rs.getString("business_partner_number")
                    ));
        } catch (EmptyResultDataAccessException e){
            return null;
        }
    }
}
