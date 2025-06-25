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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.function.Predicate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.json.*;

import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.washington.shibboleth.tools.UWHttpClient;

/**
 * Implements an access blocker for a group of users.
 * 
 * The caller provides the name of a group, a file with a list of allowed relying parties,
 * and the specified relying party being accessed.
 *
 * If the user is in the target group, then the requested RP is compared to the allow list.
 * If the RP is not in the allow list, then the test method returns true, which triggers
 * the caller to intercept the access attempt with a warning message.
 */
public class BlockSeparatedUserIntercept implements Predicate<ProfileRequestContext> {
    
    /** The value to return to indicate that access should be blocked with an error message. */
    public static final boolean BLOCK_ACCESS = true;
    /** The value to return to indicate that acess should be allowed. */
    public static final boolean NO_BLOCK = false;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(BlockSeparatedUserIntercept.class);

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
    
    /** Group id for lookup */
    @Nullable private String groupId;
    public void setGroupId(String groupId) {
        this.groupId = groupId;
        log.info("groupId = " + groupId);
    }

    /** Filename of allow list. */
    @Nullable private String allowFilename;
    public void setAllowFilename(String allowFilename) {
        this.allowFilename = allowFilename;
        log.info("allowFilename = " + allowFilename);
    }
    
    /** Last modified time of the allow list file. */
    private long lastModified = 0L;
    
    /** Internal cache of the file contents. */
    private Set<String> cachedAllowSet;

    /** Constructor. */
    public BlockSeparatedUserIntercept() {}

    /**
     * Returns true if a warning should be displayed to the user.
     */
    public boolean test(@Nullable final ProfileRequestContext input) {
        try {
            log.debug("Starting BlockAccessIntercept.test...");
            if (input == null) {return NO_BLOCK;}
            if ( (groupId == null || groupId.isEmpty()) ) {
                log.error("Misconfigured intercept: groupId not specified.");
                return NO_BLOCK;
            }
            if ( (allowFilename == null || allowFilename.isEmpty()) ) {
                log.error("Misconfigured intercept: allowFilename not specified.");
                return NO_BLOCK;
            }

            boolean isInGroup = GroupUtils.getIsInGroup(input, webClient, gwsUrlbase, groupId);
            if (!isInGroup) {
                log.debug("User is not in target group.");
                return NO_BLOCK;
            }
            
            // if here, compare the requested relying party to the allow list.
            log.info("User is in separated users control group. Checking relying party.");
            String rpid = null;
            try {
                RelyingPartyContext rpc = (RelyingPartyContext) input.getSubcontext("net.shibboleth.profile.context.RelyingPartyContext");
                rpid = rpc.getRelyingPartyId();
            } catch (Exception e) {
                log.error("RelyingPartyContext not found: ", e);
                return NO_BLOCK;
            }
            
            log.info("Relying party = '" + rpid + "'");
            Set<String> allowSet = null;
            try {
                allowSet = getAllowSet();
            } catch (Exception e) {
                log.error("Could not read allow file.");
                // Show the warning in this case. We are choosing to fail closed here.
                // Since we know the user is in the block group, assume block until proven otherwise.
                return BLOCK_ACCESS;
            }
            
            log.debug("allowSet contents:");
            for (String entityId : allowSet) {
                log.debug("entityId = '" + entityId + "'");
            }
            if (allowSet.contains(rpid)) {
                //the rpid is in the allow list, so do not block..
                log.info("RP is in the allow list, do not block access.");
                return NO_BLOCK;
            } else {
                //the rpid is not allowed, so block access.
                log.info("RP is not in the allow list, show block message.");
                return BLOCK_ACCESS;
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return NO_BLOCK;
        }
    }
    
    /**
     * Gets the set of allowed RPs. This method checks the timestamp on the file
     * and re-reads the file if it has been modified. This method is synchronized
     * so that only one thread will read the file when needed.
     */
    private synchronized Set<String> getAllowSet() {
        try {
            File allowFile = new File(this.allowFilename);
            long fileLastModified = allowFile.lastModified();
            log.debug("allowFile = " + allowFile);
            log.debug("fileLastModified = " + fileLastModified);
            log.debug("this.lastModified = " + this.lastModified);
            if (this.lastModified < fileLastModified) {
                log.debug("Reading allow file...");
                this.cachedAllowSet = readAllowFile(allowFile);
                this.lastModified = fileLastModified;
            }
            log.debug("cachedAllowSet.size() = " + this.cachedAllowSet.size());
            for (String site : this.cachedAllowSet) {
                log.debug("site = " + site);
            }
            return this.cachedAllowSet;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return new LinkedHashSet<String>();
        }
    }
    
    private Set<String> readAllowFile(File allowFile) throws Exception {
        Set<String> allowSet = new LinkedHashSet<String>();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(allowFile));
            String line = reader.readLine();
            while (line != null) {
                // Ignore comment lines that start with a '#' character.
                if (!line.startsWith("#")) {
                    String trimmedLine = line.trim();
                    // Ignore lines that are only whitespace with no content.
                    if (trimmedLine.length() > 0) {
                        allowSet.add(line.trim());
                    }
                }
                line = reader.readLine();
            }
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception ce) {
                    log.error("Error closing file: " + ce.getMessage());
                }
            }
        }
        return allowSet;
    }
}
