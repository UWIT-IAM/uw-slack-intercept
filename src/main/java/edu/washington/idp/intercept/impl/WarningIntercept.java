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
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.ArrayList;
import java.util.List;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.json.*;

import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import org.opensaml.profile.context.ProfileRequestContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.washington.shibboleth.tools.UWHttpClient;

/**
 * Determines if a warning message should be displayed for certain logins.
 * The caller can specify a targetRpid, a groupId, or both.
 *
 * If the caller specifies a targetRpid, the warning will only be displayed for requests from that RP.
 *
 * If the caller specifies a groupId, the warning will only be displayed if the username is in
 * a UW group that matches that groupId (combination of the gwUrlBase and the groupId).
 */
public class WarningIntercept implements Predicate<ProfileRequestContext> {

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(WarningIntercept.class);

    /** Lookup strategy for username. */
    @Nonnull private Function<ProfileRequestContext,String> usernameLookupStrategy;

    /** Web Client */
    UWHttpClient webClient;
    public void setWebClient(UWHttpClient v) {
       webClient = v;
       log.debug("set webclient");
    }
    public UWHttpClient getWebClient() {
       log.debug("get webclient");
       return (webClient);
    }

    /** GWS base. */
    @Nullable private String gwsUrlbase;
    public void setGwsUrlbase(String v) {
       gwsUrlbase = v;
       log.info("gwsUrlbase = " + gwsUrlbase);
    }
    
    /** RP id for Google. */
    @Nullable private String targetRpid;
    public void setTargetRpid(String targetRpid) {
        this.targetRpid = targetRpid;
        log.info("targetRpid = " + targetRpid);
    }
    
    /** Group id for lookup */
    @Nullable private String groupId;
    public void setGroupId(String groupId) {
        this.groupId = groupId;
        log.info("groupId = " + groupId);
    }

    /** Constructor. */
    public WarningIntercept() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
    }

    /**
     * Returns true if a warning should be displayed to the user.
     * Executes a GWS call to see if the user is in a specified group.
     */
    public boolean test(@Nullable final ProfileRequestContext input) {
        try {
            if (input == null) {return false;}
            if ( (targetRpid == null || targetRpid.isEmpty()) && (groupId == null || groupId.isEmpty()) ) {
                log.error("Misconfigured intercept: caller must set either targetRpid or groupId.");
                return false;
            }
            
            String rpid = null;
            if (targetRpid != null && !targetRpid.isEmpty()) {
                //verify that the relying party matches
                try {
                    RelyingPartyContext rpc = (RelyingPartyContext) input.getSubcontext("net.shibboleth.profile.context.RelyingPartyContext");
                    rpid = rpc.getRelyingPartyId();
                } catch (Exception e) {
                    log.error("RelyingPartyContext not found: ", e);
                    return false;
                }
                if (!targetRpid.equals(rpid)) {
                    log.debug("Relying party does not match the target, exiting.");
                    return false;
                }
            }
            
            if (groupId == null || groupId.isEmpty()) {
                // Warning for every user of this RP.
                log.info("Warning enabled for all users of rp: " + targetRpid);
                return true;
            } else {
                // Get the login id.
                SubjectContext subject = input.getSubcontext(SubjectContext.class);
                if (subject == null) {
                    log.warn("No subject context found");
                    return false;
                }
                
                String username = subject.getPrincipalName();
                if (username == null) {
                    log.warn("No principal name available");
                    return false;
                }
                log.debug("user " + username + " found in SubjectContext");
                
                // Make the GWS call
                try {
                    log.info("Warning lookup: user={}, rp={}", username, rpid);
                    String resp = null;
                    long startDttm = System.currentTimeMillis();
                    try {
                        resp = webClient.getResource(gwsUrlbase + groupId + "/effective_member/" + username);
                    } finally {
                        long duration = System.currentTimeMillis() - startDttm;
                        log.info("Warning lookup finish: user={}, rp={}, time={}", username, rpid, duration);
                    }
                    
                    if (resp == null) {
                        log.info("null response from gws, for user={}, rp={}", username, rpid);
                        return false;
                    }
                    // log.debug("response from gws, for " + rpid + ": " + resp);
                    JsonObject jresp = Json.createReader(new StringReader(resp)).readObject();
                    JsonArray data = jresp.getJsonArray("data");
                    if (data == null) {
                        log.info("not there response from gws, for " + username);
                        return false;
                    }
                    if (data.size() == 0) {
                        log.info("no records response from gws, for " + username);
                        return false;
                    }
                    for (JsonValue mbr : data) {
                        JsonObject jmbr = (JsonObject) mbr;
                        String id = jmbr.getString("id");
                        log.debug(".. user " + id + " OK");
                        if (id.equals(username)) {
                            log.info(username + " is a member of group: " + groupId);
                            return true;
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
                    return false;  // shouldn't get here
                } catch (Exception e) {
                    log.error("intercept/gws lookup failed: ", e);
                }
            }
        } catch (Exception e) {
            log.error("Exception executing warning intercept: ", e);
        }
        return false;
    }
}
