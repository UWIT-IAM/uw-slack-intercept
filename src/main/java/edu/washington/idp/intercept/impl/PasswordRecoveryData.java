/* ========================================================================
* Copyright (c) 2023 The University of Washington
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* ========================================================================
*/
package edu.washington.idp.intercept.impl;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This data class stores group memberships for a specific user that are relevant to the
 * password recovery interceptor. Since there are multiple relevant groups, this class
 * will collect all the memberships so they can be processed by different functions.
 * The load time is included to support a time-based cache of this data.
 */
public class PasswordRecoveryData {
    
    /**
     * A reasonable cache time is needed so that Shibboleth can iterate through the
     * various warnings without triggering new batches of groups lookups for each.
     * However, the cache time needs to be short enough that when the user goes to Identity
     * and fixes their settings, which will remove them from the relevant groups,
     * the cache will have expired by the time they come back.
     * A cache time of 30 seconds seems reasonable.
     */
    public static final long CACHE_LIFETIME = 1000*30L; // 30 seconds, in milliseconds
    
    private String username;
    private Map<String, Boolean> groupMap = new LinkedHashMap<String, Boolean>();
    private long createTime;
    private boolean isCacheable = true;
    
    public PasswordRecoveryData(String username) {
        this.username = username;
        this.createTime = System.currentTimeMillis();
    }
    
    public String getUsername() {
        return username;
    }
    
    /**
     * Returns true if the data in this object is valid. Calculated by comparing the current time
     * (in milliseconds) to the creation time, returning true if that time is less than the defined
     * CACHE_LIFETIME. That calculation can be overridded by calling the setNoCache method,
     * which wil mark the data as invalid regardless of the creation time.
     * @return true if the data is valid, false otherwise
     */
    public boolean isValid() {
        return isCacheable && ((System.currentTimeMillis() - createTime) < CACHE_LIFETIME);
    }
    
    /**
     * Sets this data object to be not cacheable. This is normally used when the loaded data
     * was partially incomplete and therefore should not be cached.
     */
    public void setNoCache() {
        this.isCacheable = false;
    }
    
    public boolean getIsInGroup(String groupId) {
        Boolean obj = groupMap.get(groupId);
        return (obj == null) ? false : obj;
    }
    
    public void setIsInGroup(String groupId, boolean value) {
        groupMap.put(groupId, value);
    }
}
