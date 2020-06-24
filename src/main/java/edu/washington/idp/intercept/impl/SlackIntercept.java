/* ========================================================================
 * Copyright (c) 2018 The University of Washington
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

import java.lang.IllegalArgumentException;
import java.lang.ClassNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import java.net.URLEncoder;

import javax.json.*;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.FunctionSupport;

import org.opensaml.profile.context.ProfileRequestContext;
import net.shibboleth.idp.authn.context.SubjectContext;

import com.google.common.base.Function;
import com.google.common.base.Predicate;

import edu.washington.shibboleth.tools.UWHttpClient;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * <code>SlackIntercept</code> methods for intercepting Slack (and others) logins
 */
public class SlackIntercept {

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(SlackIntercept.class);

    /** Lookup strategy for username. */
    @Nonnull private Function<ProfileRequestContext,String> usernameLookupStrategy;

    /** Attempted username. */
    @Nullable @NotEmpty private String username;

    /** Web Client */
    UWHttpClient webClient;
    public void setWebClient(UWHttpClient v) {
       webClient = v;
       log.info("set webclient");
    }
    public UWHttpClient getWebClient() {
       log.info("set webclient");
       return (webClient);
    }

    /** GWS base. */
    @Nullable private String gwsUrlbase;
    public void setGwsUrlbase(String v) {
       gwsUrlbase = v;
       log.info("gwsUrlbase = " + gwsUrlbase);
    }

    /** Constructor. */
    public SlackIntercept() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
    }

    public boolean testSlack(@Nullable final ProfileRequestContext input) {
        SubjectContext subject = input.getSubcontext(SubjectContext.class);
        if (subject == null) {
            log.warn("No subject context found");
            return true;  // fail pass
        }
       
        username = subject.getPrincipalName();
        if (username == null) {
            log.warn("No principal name available to check Slack status");
            // ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return true;  // fail pass
        }
        log.debug("user " + username + " found in SubjectContext");

        // see if user has the Slack group membership - assume yes on errors

        /// get the domain part of the rpid
        String rpid = null;
        try {
           RelyingPartyContext rpc = (RelyingPartyContext) input.getSubcontext("net.shibboleth.idp.profile.context.RelyingPartyContext");
           rpid = rpc.getRelyingPartyId();
        } catch (ClassNotFoundException e) {
           log.error("Slack lookup RPC not found: ", e);
           return true;
        }
        log.info("Slack lookup: user={}, rp={}", username, rpid);
        if (rpid.startsWith("http://")) rpid = rpid.substring(7);
        else if (rpid.startsWith("https://")) rpid = rpid.substring(8);
        else if (rpid.startsWith("oidc/")) rpid = rpid.substring(5);
        else rpid = rpid.replaceAll(":", "-");
        if (rpid.indexOf("/")>0) rpid = rpid.substring(0, rpid.indexOf("/"));
        if (!Pattern.matches("[0-9a-zA-Z\\-\\.]+", rpid)) {
           log.info(".. rpid {} not acceptable", rpid);
           return false;
        }
        log.info("Authz group is: " + rpid);
        try {
           String resp = webClient.getResource(gwsUrlbase + rpid + "/effective_member/" + username);
           if (resp == null) {
             log.info("null response from gws, for " + rpid);
             return true;
           }
           // log.debug("response from gws, for " + rpid + ": " + resp);
           JsonObject jresp = Json.createReader(new StringReader(resp)).readObject();
           JsonArray data = jresp.getJsonArray("data");
           if (data == null) {
             log.info("not there response from gws, for " + username);
             return false;
           }
           for (JsonValue mbr : data) {
              JsonObject jmbr = (JsonObject) mbr;
              String id = jmbr.getString("id");
              log.debug(".. user " + id + " OK");
              if (id.equals(username)) return true;
           }
           return false;  // shouldn't get here
        } catch (Exception e) {
           log.error("gws lookup failed: ", e);
        }
        return true;
    }


    public String urlEncode(String url, String didit_arg) {
        String sep = "?";
        if (url.contains("?")) sep = "&";
        String ret = URLEncoder.encode(url + sep + didit_arg);
        log.info("google encoder. in={}, out={}", url, ret);
        return ret;
    }

    // note. includes the '?' or '&'
    public String urlEncode(String url) {
        String sep = "?";
        if (url.contains("?")) sep = "&";
        String ret = URLEncoder.encode(url + sep);
        log.info("google encoder. in={}, out={}", url, ret);
        return ret;
    }
}
