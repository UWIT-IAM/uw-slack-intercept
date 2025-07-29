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

import java.util.function.Predicate;
import java.util.HashMap;
import java.util.Map;
import java.util.LinkedHashMap;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.json.*;

import net.shibboleth.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.washington.shibboleth.tools.UWHttpClient;

/**
 * Implements an intercept for users who do not have password recovery settings in place,
 * as determined by control groups that define these populations. Such users will receive
 * a warning after authentication that they should do this, and at some point (again defined
 * by group membership) be required to complete this before continuing to their requested site.
 * 
 * The caller provides the base url for GWS lookups, the entityID of the Identity.UW site
 * (which needs to be excluded from this interceptor, to allow users to completed the required
 * process at that site), and the names of the multiple relevant control groups. The caller
 * also provides the relying party being requested and the specific warning (of several) to test.
 *
 * There are multiple different warnings that could be displayed, each controlled by different groups.
 * The caller sets the name of the group to be tested before calling the test method. The expectation
 * is that the caller will call the test method multiple times, once for each possible warning. The
 * test method will return true for the warning that should be displayed (if any) and false for the others.
 * To optimize performance, the test method fetches and caches the user's group data so that all
 * tests beyond the first are fast lookups on previously loaded data.
 */
public class PasswordRecoveryIntercept implements Predicate<ProfileRequestContext> {
    
    /** Boolean value to indicate that no warning should be displayed. **/
    public static final boolean NO_WARNING = false;
    /** Boolean value indicating that a warning should be displayed. **/
    public static final boolean SHOW_WARNING = true;
    
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
    
    /** entityID for the site used for password recovery settings **/
    @Nullable private String passwordEntityId;
    public void setPasswordEntityId(String passwordEntityId) {
        this.passwordEntityId = passwordEntityId;
        log.debug("passwordEntityId = " + passwordEntityId);
    }
    
    /** Group id for the warning group **/
    @Nullable private String warningGroupId;
    public void setWarningGroupId(String warningGroupId) {
        this.warningGroupId = warningGroupId;
        log.debug("warningGroupId = " + warningGroupId);
    }
    
    /** Group id for the block group **/
    @Nullable private String blockGroupId;
    public void setBlockGroupId(String blockGroupId) {
        this.blockGroupId = blockGroupId;
        log.debug("blockGroupId = " + blockGroupId);
    }
    
    /** Group id for the staff group **/
    @Nullable private String staffGroupId;
    public void setStaffGroupId(String staffGroupId) {
        this.staffGroupId = staffGroupId;
        log.debug("staffGroupId = " + staffGroupId);
    }
    
    /** Group id for the faculty group **/
    @Nullable private String facultyGroupId;
    public void setFacultyGroupId(String facultyGroupId) {
        this.facultyGroupId = facultyGroupId;
        log.debug("facultyGroupId = " + facultyGroupId);
    }
    
    /** Group id for the student group **/
    @Nullable private String studentsGroupId;
    public void setStudentsGroupId(String studentsGroupId) {
        this.studentsGroupId = studentsGroupId;
        log.debug("studentsGroupId = " + studentsGroupId);
    }
    
    /** Group that should be tested. Will vary between different calls. **/
    @Nullable private String groupToCheck;
    public void setGroupToCheck(String groupToCheck) {
        this.groupToCheck = groupToCheck;
    }
    
    /** Private cache of group data for users **/
    private static Map<String, PasswordRecoveryData> dataCache = new HashMap<String, PasswordRecoveryData>();

    /** Constructor. */
    public PasswordRecoveryIntercept() {}
    
    /**
     * Utility method to get group data for a user. If a cached data object is available
     * and valid, use it, otherwise create and cache a new object.
     */
    private PasswordRecoveryData getPasswordRecoveryData(String username) {
        PasswordRecoveryData cachedData = loadDataFromCache(username);
        if (cachedData != null && cachedData.isValid()) {
            return cachedData;
        } else {
            try {
                PasswordRecoveryData newData = loadDataFromGws(username);
                storeDataToCache(username, newData);
                return newData;
            } catch (Exception e) {
                log.error(e.getMessage(), e);
                return null;
            }
        }
    }
    
    /**
     * Synchronized method to get data from the cache.
     */
    private static synchronized PasswordRecoveryData loadDataFromCache(String username) {
        return dataCache.get(username);
    }
    
    /**
     * Synchronized method to put data into the cache.
     */
    private static synchronized void storeDataToCache(String username, PasswordRecoveryData data) {
        dataCache.put(username, data);
    }
    
    /**
     * Method to load group data from GWS.
     */
    private PasswordRecoveryData loadDataFromGws(String username) throws Exception {
        PasswordRecoveryData data = new PasswordRecoveryData(username);
        data.setIsInGroup(warningGroupId, GroupUtils.getIsInGroup(username, webClient, gwsUrlbase, warningGroupId) );
        // If the user is not in the warning group, then they cannot be in any of the other groups.
        // Therefore only check the others if they are in the warning group.
        if (data.getIsInGroup(warningGroupId)) {
            //Check these groups, catching exceptions. If any of these lookups fail, at least the presence
            //in the base group will trigger a warning.
            tryLoadDataFromGws(username, blockGroupId, data);
            tryLoadDataFromGws(username, staffGroupId, data);
            tryLoadDataFromGws(username, facultyGroupId, data);
            tryLoadDataFromGws(username, studentsGroupId, data);
        } else {
            data.setIsInGroup(blockGroupId, false);
            data.setIsInGroup(staffGroupId, false);
            data.setIsInGroup(facultyGroupId, false);
            data.setIsInGroup(studentsGroupId, false);
        }
        return data;
    }
    
    /**
     * Attempt to load group data from GWS, trapping exceptions. If the data cannot be loaded,
     * an error will be logged, the relevant data field will be set to false, and the data will be
     * marked as non-cacheable.
     * @param username the user to check
     * @param groupId the group to check
     * @param data the data object to populate
     */
    private void tryLoadDataFromGws(String username, String groupId, PasswordRecoveryData data) {
        try {
            data.setIsInGroup(groupId, GroupUtils.getIsInGroup(username, webClient, gwsUrlbase, groupId) );
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            data.setIsInGroup(groupId, false);
            data.setNoCache();
        }
    }

    /**
     * Returns true if the warning specified by the groupToCheck input should be displayed to the user.
     *
     * If the target site is the Identity.UW site where the user could set their password recovery options,
     * return null to allow the user through. If the user is not in the main control group, return null
     * as this means the user has nothing to do.
     * Otherwise, check membership in the block group; if present, return true if the block page
     * is being tested. Otherwise check for membership in various population-specific groups;
     * if present, return true if the corresponding warning is being tested. Otherwise return true
     * if the generic warning message is being tested.
     */
    public boolean test(@Nullable final ProfileRequestContext input) {
        try {
            log.debug("starting PasswordRecoveryIntercept.test...");
            // if the inputs are not valid, this call will log errors and return false,
            // in which case we will not show a warning.
            if ( !validateInputs() ) {return NO_WARNING;}
            
            // If the requested site is the actual site used to set password recovery options,
            // we do not want to block them. Also do not block if we cannot identify the requested site.
            String targetEntityId = null;
            try {
                RelyingPartyContext rpc = (RelyingPartyContext) input.getSubcontext("net.shibboleth.profile.context.RelyingPartyContext");
                targetEntityId = rpc.getRelyingPartyId();
            } catch (Exception e) {
                log.error("RelyingPartyContext not found: ", e);
                return NO_WARNING;
            }
            if (targetEntityId == null || passwordEntityId.equals(targetEntityId)) {return NO_WARNING;}

            // Get the username. If not available, this call will log an error and return null,
            // in which case we will not show a warning.
            String username = GroupUtils.getUsername(input);
            if (username == null) {return NO_WARNING;}
            
            // Get the relevant group data. If not available, this call will log an error and return null,
            // in which case we will not show a warning.
            PasswordRecoveryData data = getPasswordRecoveryData(username);
            if (data == null) {return NO_WARNING;}
            
            
            // If the user is not in the warning group, do not show any warning.
            if (!data.getIsInGroup(warningGroupId)) {return NO_WARNING;}
            
            // The user is in the warning group. They should be in none, or exactly one,
            // of the other groups, but we will not trust that that is the case. Instead,
            // we will test the membership in an ordered list of groups, each of which
            // should trigger a specific warning.
            
            if (data.getIsInGroup(blockGroupId)) {
                //The user is in the block group. Break processing here.
                //If the caller is looking for the block group, return SHOW_WARNING to show the block message,
                //otherwise return NO_WARNING to not show other messages.
                if (groupToCheck.equals(blockGroupId)) {
                    log.info("PASSWORD_RECOVERY_BLOCK, user = " + username);
                    return SHOW_WARNING;
                } else {
                    return NO_WARNING;
                }
            } else if (data.getIsInGroup(staffGroupId)) {
                //The user is NOT in the block group, but IS in the staff group.
                //Again, return SHOW_WARNING iff the caller is looking for the staff warning.
                if (groupToCheck.equals(staffGroupId)) {
                    log.info("PASSWORD_RECOVERY_STAFF, user = " + username);
                    return SHOW_WARNING;
                } else {
                    return NO_WARNING;
                }
            } else if (data.getIsInGroup(facultyGroupId)) {
                //Same as above, but now for the faculty group/faculty warning.
                if (groupToCheck.equals(facultyGroupId)) {
                    log.info("PASSWORD_RECOVERY_FACULTY, user = " + username);
                    return SHOW_WARNING;
                } else {
                    return NO_WARNING;
                }
            } else if (data.getIsInGroup(studentsGroupId)) {
                //Same as above, but now for the students group/students warning.
                if (groupToCheck.equals(studentsGroupId)) {
                    log.info("PASSWORD_RECOVERY_STUDENTS, user = " + username);
                    return SHOW_WARNING;
                } else {
                    return NO_WARNING;
                }
            } else {
                //The user is in none of the other groups, so return true iff the caller
                //is looking for the basic warning group.
                if (groupToCheck.equals(warningGroupId)) {
                        log.info("PASSWORD_RECOVERY_MESSAGE, user = " + username);
                    return SHOW_WARNING;
                } else {
                    return NO_WARNING;
                }
            }
        } catch (Exception e) {
            //If something unexpected goes wrong, log the error and show no warning.
            log.error(e.getMessage(), e);
            return NO_WARNING;
        }
    }
    
    /**
     * Verify the input data set by the caller. Each required field will be tested independently.
     * If all are valid, return true; otherwise log an error message for each invalid field
     * and return false.
     * @return true iff all fields are valid, false otherwise
     */
    public boolean validateInputs() {
        boolean isValid = true;
        if (webClient == null) {
            log.error("Misconfigured intercept: webClient not provided.");
            isValid = false;
        }
        if (gwsUrlbase == null || gwsUrlbase.length() == 0) {
            log.error("Misconfigured intercept: webClient not provided.");
            isValid = false;
        }
        if (passwordEntityId == null || passwordEntityId.length() == 0) {
            log.error("Misconfigured intercept: passwordEntityId not provided.");
            isValid = false;
        }
        if (warningGroupId == null || warningGroupId.length() == 0) {
            log.error("Misconfigured intercept: warningGroupId not provided.");
            isValid = false;
        }
        if (blockGroupId == null || blockGroupId.length() == 0) {
            log.error("Misconfigured intercept: blockGroupId not provided.");
            isValid = false;
        }
        if (staffGroupId == null || staffGroupId.length() == 0) {
            log.error("Misconfigured intercept: staffGroupId not provided.");
            isValid = false;
        }
        if (facultyGroupId == null || facultyGroupId.length() == 0) {
            log.error("Misconfigured intercept: facultyGroupId not provided.");
            isValid = false;
        }
        if (studentsGroupId == null || studentsGroupId.length() == 0) {
            log.error("Misconfigured intercept: studentsGroupId not provided.");
            isValid = false;
        }
        if (groupToCheck == null || groupToCheck.length() == 0) {
            log.error("Misconfigured intercept: groupToCheck not provided.");
            isValid = false;
        }
        return isValid;
    }
}
