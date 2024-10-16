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
public class ConnectorRepository {
    private final JdbcTemplate jdbcTemplate;

    public ConnectorRepository(JdbcTemplate jdbcTemplate){
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<ConnectorDTO> getAllConnectors(){
        String sql = "SELECT connector_url,host_id FROM portal.connectors";
        return jdbcTemplate.query(sql, (rs, rowNum) ->
                new ConnectorDTO(
                        rs.getString("connector_url"),
                        rs.getString("host_id")
                ));
    }

    public ConnectorDTO getConnector(String connector_url, String host_id){
        String sql = "SELECT connector_url,host_id FROM portal.connectors WHERE connector_url = ? AND host_id = CAST(? AS UUID)";
        try {
            return jdbcTemplate.queryForObject(sql, new Object[]{ connector_url, host_id }, (rs, rowNum) ->
                    new ConnectorDTO(
                            rs.getString("connector_url"),
                            rs.getString("host_id")
                    ));
        } catch (EmptyResultDataAccessException e){
            return null;
        }
    }
}
