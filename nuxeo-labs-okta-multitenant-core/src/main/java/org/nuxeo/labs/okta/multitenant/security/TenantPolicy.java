package org.nuxeo.labs.okta.multitenant.security;


import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.query.sql.NXQL;
import org.nuxeo.ecm.core.query.sql.model.*;
import org.nuxeo.ecm.core.security.AbstractSecurityPolicy;

import java.security.Principal;
import java.util.List;


public class TenantPolicy extends AbstractSecurityPolicy {

    @Override
    public Access checkPermission(Document document, ACP mergedAcp, Principal principal,
                                  String permission, String[] resolvedPermissions,
                                  String[] additionalPrincipals) {

        if (isSuperUser(principal)) {
            // Use ACL for for admins and system users
            return Access.UNKNOWN;
        }

        NuxeoPrincipal nxPrincipal = (NuxeoPrincipal) principal;
        String tenant = nxPrincipal.getTenantId();

        String path = document.getPath();

        if (path.equals("/") || path.startsWith("/"+tenant)) {
            // Use ACL
            return Access.UNKNOWN;
        } else {
            // Deny access because document does not belong to the same tenant as the user
            return Access.DENY;
        }
    }

    @Override
    public boolean isExpressibleInQuery(String repositoryName) {
        return true;
    }

    @Override
    public SQLQuery.Transformer getQueryTransformer(String repositoryName) {
        return CONFIDENTIALITY_TRANSFORMER;
    }

    public static final SQLQuery.Transformer CONFIDENTIALITY_TRANSFORMER = new ConfidentialityTransformer();

    public static class ConfidentialityTransformer implements SQLQuery.Transformer {

        // NOT (ecm:path STARTSWITH '/tenantID')

        @Override
        public SQLQuery transform(Principal principal, SQLQuery query) {

            if (isSuperUser(principal)) {
                // don't modify the query for admins and system users
                return query;
            }

            // return query with updated WHERE clause
            return new SQLQuery(
                    query.select,
                    query.from,
                    buildWhereClause(query.where, (NuxeoPrincipal) principal),
                    query.groupBy,
                    query.having,
                    query.orderBy,
                    query.limit,
                    query.offset);
        }

        public WhereClause buildWhereClause(WhereClause originalWhere,NuxeoPrincipal principal) {
            Predicate pr1 = new Predicate(
                    new Reference(NXQL.ECM_PATH),
                    Operator.STARTSWITH,
                    new StringLiteral("/"+principal.getName()));

            Predicate pr2 = new Predicate(
                    new Reference(NXQL.ECM_PATH),
                    Operator.STARTSWITH,
                    new StringLiteral("/"));

            Predicate filter = new Predicate(pr1, Operator.OR, pr2);

            if (originalWhere == null || originalWhere.predicate == null) {
                return new WhereClause(filter);
            } else {
                return new WhereClause(new Predicate(originalWhere.predicate, Operator.AND, filter));
            }

        }
    }

    /**
     *
     * @param principal
     * @return true if the principal is admin por system
     */
    public static boolean isSuperUser(Principal principal) {
        NuxeoPrincipal nxPrincipal = (NuxeoPrincipal) principal;
        List<String> groups = nxPrincipal.getGroups();
        return "system".equals(principal.getName()) || groups.contains("administrators");
    }

}
