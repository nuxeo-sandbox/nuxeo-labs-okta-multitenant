/*
 * (C) Copyright 2014 Nuxeo SA (http://nuxeo.com/) and others.
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
 *
 * Contributors:
 *     Michael Vachette
 */
package org.nuxeo.labs.okta.multitenant.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.*;
import org.nuxeo.ecm.platform.auth.saml.SAMLCredential;
import org.nuxeo.ecm.platform.auth.saml.user.AbstractUserResolver;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OktaUserResolver extends AbstractUserResolver {

    private static final Log log = LogFactory.getLog(OktaUserResolver.class);


    @Override
    public void init(Map<String, String> map) {
        //nothing
    }

    @Override
    public String getLoginName(SAMLCredential samlCredential) {
        return null;
    }

    @Override
    public String findOrCreateNuxeoUser(SAMLCredential userInfo) {
        String username = findNuxeoUser(userInfo);
        if (username == null) {
            DocumentModel userDoc = createNuxeoUser(userInfo);
            return userDoc.getId();
        } else {
            UserManager userManager = Framework.getLocalService(UserManager.class);
            updateUserInfo(userManager.getUserModel(username), userInfo);
            return username;
        }
    }

    public String findNuxeoUser(SAMLCredential credential) {

        try {
            UserManager userManager = Framework.getLocalService(UserManager.class);
            Map<String, Serializable> query = new HashMap<>();
            query.put(userManager.getUserEmailField(), credential.getNameID().getValue());
            DocumentModelList users = userManager.searchUsers(query, null);
            if (users.isEmpty()) {
                return null;
            }
            return (String) users.get(0).getPropertyValue(userManager.getUserIdField());

        } catch (NuxeoException e) {
            log.error(
                    "Error while search user in UserManager using email " +
                            credential.getNameID().getValue(), e);
            return null;
        }
    }

    public DocumentModel createNuxeoUser(SAMLCredential credential) {
        DocumentModel userDoc;
        try {
            UserManager userManager = Framework.getService(UserManager.class);
            userDoc = userManager.getBareUserModel();
            userDoc.setPropertyValue(userManager.getUserIdField(), credential.getNameID().getValue());
            userDoc = userManager.createUser(userDoc);
            userDoc = updateUserInfo(userDoc,credential);
        } catch (NuxeoException e) {
            log.error(
                    "Error while creating user " +
                            credential.getNameID().getValue() + "in UserManager", e);
            return null;
        }
        return userDoc;
    }

    public DocumentModel updateUserInfo(DocumentModel user, SAMLCredential credential) {
        try {
            UserManager userManager = Framework.getLocalService(UserManager.class);
            NuxeoPrincipal principal =
                    userManager.getPrincipal((String) user.getPropertyValue(userManager.getUserIdField()));
            principal.setEmail(credential.getNameID().getValue());
            for (Attribute attribute: credential.getAttributes()) {
                switch (attribute.getName()) {
                    case "firstName" :
                        principal.setFirstName(attribute.getAttributeValues().get(0).getDOM().getTextContent());break;
                    case "lastName" :
                        principal.setLastName(attribute.getAttributeValues().get(0).getDOM().getTextContent());break;
                    case "organization":
                        principal.setCompany(attribute.getAttributeValues().get(0).getDOM().getTextContent());
                        principal.getModel().setPropertyValue("user:tenantId",principal.getCompany());
                        break;
                    case "groups":addToGroups(attribute,principal);break;
                    default:break;
                }
            }
            userManager.updateUser(principal.getModel());
            return userManager.getUserModel(principal.getName());

        } catch (NuxeoException e) {
            log.error(
                    "Error while search user in UserManager using email " +
                            credential.getNameID().getValue(), e);
            return null;
        }
    }

    protected void addToGroups(Attribute attribute, NuxeoPrincipal principal) {
        List<String> groups = principal.getGroups();
        for (XMLObject value : attribute.getAttributeValues()) {
            String group = value.getDOM().getTextContent();
            if ("Everyone".equals(group)) {
                //groups.add("members");
                // do nothing
            } else if ("Tenant_ADMIN".equals(group)) {
                CoreSession session = CoreInstance.openCoreSessionSystem("default");
                String query = String.format(
                        "Select * From Document WHERE tenantconfig:tenantId = '%s'",
                        principal.getCompany());
                DocumentModel tenant = session.query(query).get(0);
                List<String> adminsList = (List<String>) tenant.getPropertyValue("tenantconfig:administrators");
                if (!adminsList.contains(principal.getName())) {
                    adminsList.add(principal.getName());
                }
                tenant.setPropertyValue("tenantconfig:administrators", (Serializable) adminsList);
                session.saveDocument(tenant);
                session.save();
            } else {
                groups.add("tenant_"+principal.getTenantId()+"_"+group);
            }
        }
        principal.setGroups(groups);
    }

}
