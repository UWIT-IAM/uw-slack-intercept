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

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import jakarta.json.*;

import net.shibboleth.idp.authn.context.SubjectContext;
import org.opensaml.profile.context.ProfileRequestContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.washington.shibboleth.tools.UWHttpClient;

/**
 * Utilities for working with UW Groups.
 */
public class GroupUtils {
    
    public static final boolean USER_IN_GROUP = true;
    public static final boolean NOT_USER_IN_GROUP = false;
    
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(GroupUtils.class);
    
    /**
     * Returns true if the authenticated user is in the target group.
     * @param input the context object from which the username is obtained
     * @param webClient the web client to use to make the call
     * @param gwsUrlbase the base of the groups URL to build the final URL
     * @param groupId the name/id of the group to check
     * @return true if the user is in the group, false if not
     * @throws Exception if any occur while performing the call
     */
    public static boolean getIsInGroup(final ProfileRequestContext input, UWHttpClient webClient, String gwsUrlbase, String groupId) throws Exception {
        // Get the login id.
        SubjectContext subject = input.getSubcontext(SubjectContext.class);
        if (subject == null) {
            log.warn("No subject context found");
            return NOT_USER_IN_GROUP;
        }
        
        String username = subject.getPrincipalName();
        if (username == null) {
            log.warn("No principal name available");
            return NOT_USER_IN_GROUP;
        }
        log.debug("user " + username + " found in SubjectContext");
        return getIsInGroup(username, webClient, gwsUrlbase, groupId);
    }
    
    /**
     * Returns true if the specified user is in the target group.
     * All arguments are required.
     * @param username the identifier of the user to check
     * @param webClient the web client to use to make the call
     * @param gwsUrlbase the base of the groups URL to build the final URL
     * @param groupId the name/id of the group to check
     * @return true if the user is in the group, false if not
     * @throws Exception if any occur while performing the call
     */
    public static boolean getIsInGroup(String username, UWHttpClient webClient, String gwsUrlbase, String groupId) throws Exception {
        // Make the GWS call
        log.info(" gws lookup: user={}, group={}", username, groupId);
        String resp = null;
        long startDttm = System.currentTimeMillis();
        try {
            resp = webClient.getResource(gwsUrlbase + groupId + "/effective_member/" + username);
        } finally {
            long duration = System.currentTimeMillis() - startDttm;
            log.info("Warning lookup finish: user={}, group={}, time={}", username, groupId, duration);
        }
        
        if (resp == null) {
            log.info("null response from gws, for user={}, group={}", username, groupId);
            return NOT_USER_IN_GROUP;
        }
        // log.debug("response from gws, for " + rpid + ": " + resp);
        JsonObject jresp = Json.createReader(new StringReader(resp)).readObject();
        JsonArray data = jresp.getJsonArray("data");
        if (data == null) {
            log.info("not there response from gws, for " + username);
            return NOT_USER_IN_GROUP;
        }
        if (data.size() == 0) {
            log.info("no records response from gws, for " + username);
            return NOT_USER_IN_GROUP;
        }
        for (JsonValue mbr : data) {
            JsonObject jmbr = (JsonObject) mbr;
            String id = jmbr.getString("id");
            log.debug(".. user " + id + " OK");
            if (id.equals(username)) {
                log.info(username + " is a member of group: " + groupId);
                return USER_IN_GROUP;
            }
        }
        
        // If here, username was not found in the array. Log what was in the array.
        List<String> idList = new ArrayList<String>();
        for (JsonValue mbr : data) {
            JsonObject jmbr = (JsonObject) mbr;
            String id = jmbr.getString("id");
            idList.add(id);
        }
        log.info("username not found in gws data, for " + username + ", idList = " + idList);
        return NOT_USER_IN_GROUP;  // shouldn't get here
    }
}
