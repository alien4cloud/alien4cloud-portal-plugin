package org.alien4cloud.plugin.portal.modifier;

import alien4cloud.deployment.DeploymentRuntimeStateService;
import alien4cloud.deployment.DeploymentService;
import alien4cloud.model.common.Tag;
import alien4cloud.model.deployment.Deployment;
import alien4cloud.model.deployment.DeploymentTopology;
import alien4cloud.paas.IPaasEventListener;
import alien4cloud.paas.IPaasEventService;
import alien4cloud.paas.model.AbstractMonitorEvent;
import alien4cloud.paas.model.PaaSDeploymentStatusMonitorEvent;
import alien4cloud.paas.wf.validation.WorkflowValidator;
import alien4cloud.tosca.context.ToscaContextual;
import static alien4cloud.utils.AlienUtils.safe;
import alien4cloud.utils.PropertyUtil;

import org.alien4cloud.alm.deployment.configuration.flow.EnvironmentContext;
import org.alien4cloud.alm.deployment.configuration.flow.FlowExecutionContext;
import org.alien4cloud.alm.deployment.configuration.flow.TopologyModifierSupport;

import org.alien4cloud.tosca.model.definitions.AbstractPropertyValue;
import org.alien4cloud.tosca.model.definitions.ComplexPropertyValue;
import org.alien4cloud.tosca.model.definitions.ListPropertyValue;
import org.alien4cloud.tosca.model.definitions.ScalarPropertyValue;
import org.alien4cloud.tosca.model.templates.Capability;
import org.alien4cloud.tosca.model.templates.NodeTemplate;
import org.alien4cloud.tosca.model.templates.RelationshipTemplate;
import org.alien4cloud.tosca.model.templates.Topology;
import org.alien4cloud.tosca.utils.TopologyNavigationUtil;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.commons.lang.StringUtils;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import lombok.extern.slf4j.Slf4j;

import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBE_NAMESPACE;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SIMPLE_RESOURCE;

import org.alien4cloud.plugin.portal.configuration.PortalPortalConfiguration;
import org.alien4cloud.plugin.portal.model.*;
import static org.alien4cloud.plugin.portal.PortalConstants.API_SERVICE;
import static org.alien4cloud.plugin.portal.PortalConstants.IAM_APIACCESS_TYPE;
import static org.alien4cloud.plugin.portal.PortalConstants.IAM_RELATION;
import static org.alien4cloud.plugin.portal.PortalConstants.IAM_TYPE;
import static org.alien4cloud.plugin.portal.PortalConstants.PROXIED_SERVICE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.annotation.Resource;
import javax.inject.Inject;

@Slf4j
@Component("iam-manager")
public class IAMManagerModifier extends TopologyModifierSupport {

    @Inject
    private IPaasEventService eventService;

    @Inject
    private DeploymentRuntimeStateService deploymentRuntimeStateService;

    @Inject
    private DeploymentService deploymentService;

    @Resource
    protected PortalPortalConfiguration portalConfiguration;

    private final ObjectMapper mapper = new ObjectMapper();

    /* tokens per zone */
    private Map<String,Token> tokens = new HashMap<String,Token>();

    /* A4C client secret per zone */
    private Map<String,String> a4cClientSecrets = new HashMap<String,String>();

    @PostConstruct
    public void init() {
        eventService.addListener(listener);
    }

    @PreDestroy
    public void term() {
        eventService.removeListener(listener);
    }

    IPaasEventListener listener = new IPaasEventListener() {
        @Override
        public void eventHappened(AbstractMonitorEvent event) {
             handleEvent((PaaSDeploymentStatusMonitorEvent) event);
        }

        @Override
        public boolean canHandle(AbstractMonitorEvent event) {
            return (event instanceof PaaSDeploymentStatusMonitorEvent);
        }
    };

    private void handleEvent(PaaSDeploymentStatusMonitorEvent inputEvent) {
        Deployment deployment = deploymentService.get(inputEvent.getDeploymentId());

        switch(inputEvent.getDeploymentStatus()) {
            case UNDEPLOYED:
                processUnDeployment (deployment);
                break;
            default:
                return;
        }
    }
    /* get A4C client secret for one zone */
    private String getA4CClientSecret(String zone) {
       /* return secret if already got from keycloak */
       String secret = a4cClientSecrets.get(zone);
       if (secret != null) {
          return secret;
       }
       /* else get it from keycloak using a temporary token for client admin-cli */
       Token initToken = getToken (zone, "admin-cli", null);
       if ((initToken == null) || StringUtils.isBlank(initToken.getAccessToken())) {
          log.error ("No token, cannot perform");
          return null;
       }
       log.debug ("Init token {} for zone {}", initToken.getAccessToken(), zone);
       String clientId = portalConfiguration.getParameter(zone, "clientId");
       secret = getSecretFromClientId (initToken, clientId, zone);
       log.debug ("{} secret {} for zone {}", clientId, secret, zone);
       a4cClientSecrets.put (zone, secret);
       return secret;
    }

    @Override
    @ToscaContextual
    public void process(Topology topology, FlowExecutionContext context) {
        log.info("Processing topology {}" ,topology.getId());
        try {
            WorkflowValidator.disableValidationThreadLocal.set(true);
            doProcess(topology, context);
        } catch (Exception e) {
            log.warn ("Couldn't process portal publisher modifier", e);
        } finally {
            WorkflowValidator.disableValidationThreadLocal.remove();
            log.debug("Finished processing topology " + topology.getId());
        }
    }

    private void processUnDeployment (Deployment deployment) {
        log.info ("Processing undeployment " + deployment.getId());
        DeploymentTopology deployedTopology = deploymentRuntimeStateService.getRuntimeTopology(deployment.getId());
        String zone = null;

        NodeTemplate kubeNS = null;
        for (NodeTemplate node : TopologyNavigationUtil.getNodesOfType(deployedTopology, K8S_TYPES_SIMPLE_RESOURCE, false)) {
           String resource_type = PropertyUtil.getScalarValue(node.getProperties().get("resource_type"));
           if (resource_type.equals("namespaces")) {
              kubeNS = node;
           }
        }

        if (kubeNS != null) {
           try {
               ObjectNode spec = (ObjectNode) mapper.readTree(PropertyUtil.getScalarValue(kubeNS.getProperties().get("resource_spec")));
               zone = spec.with("metadata").with("labels").get("ns-zone-de-sensibilite").textValue();
           } catch(Exception e) {
               log.info("Can't find ns-zone-de-sensibilite");
           }
        } else {
           log.info ("No namespace");
        }

        if (StringUtils.isBlank(zone)) {
           log.info ("Zone not set, can not perform");
           return;
        }
        log.debug ("Zone: {}", zone);
        if (deployedTopology != null) {
           /* manage IAM clients */
           for (NodeTemplate node : TopologyNavigationUtil.getNodesOfType(deployedTopology, IAM_TYPE, false)) {
              log.debug ("Processing node {}", node.getName());
              Capability endpoint = safe(node.getCapabilities()).get("iam_endpoint");
              if (endpoint == null) {
                 log.warn ("No iam_endpoint for {}, skip it", node.getName());
                 continue;
              }
              String clientId = PropertyUtil.getScalarValue(endpoint.getProperties().get("clientId"));
              if (StringUtils.isBlank(clientId)) {
                 log.warn ("No client id for {}, skip it", node.getName());
                 continue;
              }
              disableClient (clientId, zone);
           }
        } else {
            log.error("Deployed topology is no longer available.");
        }

    }

    private void doProcess(Topology topology, FlowExecutionContext context) {
        String zone = null;
        /* get zone from namespace node */
        Set<NodeTemplate> kubeNS = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_KUBE_NAMESPACE, false);
        if ((kubeNS != null) && (kubeNS.size() > 0)) {
           NodeTemplate NS = kubeNS.iterator().next();
           try {
              ComplexPropertyValue metadata = (ComplexPropertyValue)NS.getProperties().get("metadata");
              Map<String, Object> labels = (Map<String,Object>)metadata.getValue().get("labels");
              zone = PropertyUtil.getScalarValue((ScalarPropertyValue)labels.get("ns-zone-de-sensibilite"));
           } catch(Exception e) {
              log.info("Can't find ns-zone-de-sensibilite");
           }
        } else {
           log.info ("No namespace node");
        }
        if (StringUtils.isBlank(zone)) {
           log.info ("Zone not set, can not perform");
           return;
        }
        log.debug ("Zone: {}", zone);

        Set<NodeTemplate> services = TopologyNavigationUtil.getNodesOfType(topology, PROXIED_SERVICE, true);
        for (NodeTemplate node : services) {
           manageService (topology, context, node, zone, true);
        }

        services = TopologyNavigationUtil.getNodesOfType(topology, API_SERVICE, true);
        for (NodeTemplate node : services) {
           manageService (topology, context, node, zone, false);
        }

        /* manage IAM clients */
        for (NodeTemplate node : TopologyNavigationUtil.getNodesOfType(topology, IAM_TYPE, true)) {

           Capability endpoint = safe(node.getCapabilities()).get("iam_endpoint");
           if (endpoint == null) {
              log.warn ("No iam_endpoint for {}, skip it", node.getName());
              continue;
           }

           endpoint.getProperties().put("iamInternalUrl", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "iamBaseUrl")));
           endpoint.getProperties().put("iamExternalUrl", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "iamExternalUrl")));
           endpoint.getProperties().put("openidUri", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "openidUri")));
           endpoint.getProperties().put("proxyBaseUrl", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "proxyBaseUrl")));
           endpoint.getProperties().put("proxyHostBase", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "proxyHostBase")));
           endpoint.getProperties().put("proxyHost", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "proxyHost")));
           endpoint.getProperties().put("portalExternalUrl", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "portalExternalUrl")));

           String clientId = PropertyUtil.getScalarValue(endpoint.getProperties().get("clientId"));
           if (StringUtils.isBlank(clientId)) {
             clientId = "L_ACU_" + context.getEnvironmentContext().get().getApplication().getName();
             endpoint.getProperties().put("clientId", new ScalarPropertyValue(clientId));
             log.debug ("Generating clientId: {}", clientId);
           }

           String clientSecret = createClient (clientId, endpoint.getProperties(), zone);

           if (clientSecret.equals("")) {
              context.log().warn("Can not get client secret for {}", clientId);
           }

           endpoint.getProperties().put("clientSecret", new ScalarPropertyValue(clientSecret));
        }

        /* manage IAM API Accesses */
        String user = portalConfiguration.getParameter(zone, "iamApiUser");
        String password = portalConfiguration.getParameter(zone, "iamApiPassword");
        if (!StringUtils.isBlank(user) && !StringUtils.isBlank(password)) {
           for (NodeTemplate node : TopologyNavigationUtil.getNodesOfType(topology, IAM_APIACCESS_TYPE, true)) {

              Capability endpoint = safe(node.getCapabilities()).get("iam_endpoint");
              if (endpoint == null) {
                 log.warn ("No iam_endpoint for {}, skip it", node.getName());
                 continue;
              }

              endpoint.getProperties().put("username", new ScalarPropertyValue(user));
              endpoint.getProperties().put("password", new ScalarPropertyValue(password));
           }
        }
    }

    private void manageService (Topology topology, FlowExecutionContext context, NodeTemplate node, String zone, boolean ihm) {
        Capability endpoint = safe(node.getCapabilities()).get("service_endpoint");
        if (endpoint == null) {
           log.warn ("No service_endpoint for {}, skip it", node.getName());
           return;
        }

        String url = null;
        if (ihm) {
           /* set proxied_url property for services */
           String url_path = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("url_path"));
           if (url_path == null) {
              url_path = "";
           }
           url = portalConfiguration.getParameter (zone, "proxyBaseUrl") + url_path;
           endpoint.getProperties().put("proxied_url", new ScalarPropertyValue(url));
        }

        /*--- create IAM role ---*/

        /* get module qualified name */
        Set<RelationshipTemplate> rels = TopologyNavigationUtil.getTargetRelationships(node, "expose");
        if (rels.size() == 0) {
            log.warn ("No 'expose' relation for {}, skip it", node.getName());
            return;
        }
        RelationshipTemplate rel = rels.iterator().next();
        NodeTemplate module = topology.getNodeTemplates().get(rel.getTarget());
        String qualifiedName = "not_set";
        List<Tag> tags = module.getTags();
        for (Tag tag: safe(tags)) {
           if (tag.getName().equals("qualifiedName")) {
              qualifiedName = tag.getValue();
           }
        }
        if (qualifiedName.equals("not_set")) {
           log.warn ("Cannot find qualified name for {}, skip it", module.getName());
           return;
        }
        log.debug("Module qualifiedName: {}", qualifiedName);

        String tabname = null;
        if (ihm) {
           /* look for IAM node from module relations and set proxied_url */
           Map<String, RelationshipTemplate> relationships = module.getRelationships();
           for (String nrel : safe(relationships).keySet()) {
              String reltype = relationships.get(nrel).getRequirementType();
              if (reltype.equals(IAM_RELATION)) {
                 NodeTemplate iamnode = safe(topology.getNodeTemplates()).get(relationships.get(nrel).getTarget());
                 Capability iamendpoint = safe(iamnode.getCapabilities()).get("iam_endpoint");
                 if (iamendpoint != null) {
                    iamendpoint.getProperties().put("proxied_url", new ScalarPropertyValue(url));
                 }
              }
           }

           /* get tab name */
           tabname = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("portalTabname"));
           if (StringUtils.isBlank(tabname)) {
              log.info ("Tab name not set for {}, using 'cas-usage'", node.getName());
              tabname = "cas-usage";
           }
           qualifiedName += "_IHM";
        } else {
           qualifiedName += "_" + node.getName().replaceAll("_","-");
           endpoint.getProperties().put("url_path", new ScalarPropertyValue("/" + qualifiedName));
        }

        if (!createRole (qualifiedName, tabname, zone)) {
           context.log().warn("Can not create role {}", qualifiedName);
        }
     }
    /**
     * create role in keycloak if it does not exist yet, return false if error 
     **/
    private boolean createRole (String qualifiedName, String tabname, String zone) {
       Token token = getToken(zone);

       if ((token == null) || StringUtils.isBlank(token.getAccessToken())) {
          log.error ("No token, cannot perform");
          return false;
       }

       if (!existRole(token, qualifiedName, zone)) {
          return doCreateRole (token, qualifiedName, tabname, zone);
       }

       return true;
    }

    /**
     * test whether a role exists or not
     **/
    private boolean existRole (Token token, String name, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/roles/" + name;

       StringBuffer error = new StringBuffer();
       Role result = this.<Object, Role>sendRequest (token, url, HttpMethod.GET, null, Role.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Role {} found", name);
          return true;
       } else {
          log.debug ("Role {} not found", name);
          return false;
       }
    }

    /**
     * create role, return false if error
     **/
    private boolean doCreateRole(Token token, String name, String tabname, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/roles";

       Role role = new Role();
       role.setName(name);
       role.setDescription ("Artemis role '" + name + "'");
       if (tabname != null) {
          ArrayList tabs = new ArrayList();
          tabs.add(tabname);
          HashMap<String,List<String>> attrs = new HashMap<String,List<String>>();
          attrs.put ("tabname", tabs);
          role.setAttributes(attrs);
       }

       /* create role */
       StringBuffer error = new StringBuffer();
       String result = this.<Role, String>sendRequest (token, url, HttpMethod.POST, role, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Role {} created", name);
       } else {
          log.error ("Cannot create role {}", name);
          return false;
       }

       if (tabname != null) {
          /* update role (to set tabname) */
          error = new StringBuffer();
          url = url + "/" + name;
          result = this.<Role, String>sendRequest (token, url, HttpMethod.PUT, role, String.class, zone, true, error);
          if (error.length()==0) {
             log.debug ("Role {} updated", name);
          } else {
             log.error ("Cannot update role {}", name);
             return false;
          }
       }
       return true;
    }

    /**
     * create client in keycloak if it does not exist yet, return client secret 
     **/
    private String createClient (String clientId, Map<String, AbstractPropertyValue> props, String zone) {
       Token token = getToken(zone);

       if ((token == null) || StringUtils.isBlank(token.getAccessToken())) {
          log.error ("No token, cannot perform");
          return "";
       }

       Client client = getClient(token, clientId, zone);
       if (client == null) {
          doCreateClient(token, clientId, props, zone);
          client = getClient(token, clientId, zone);
       }
       if (client == null)
       {
          return "";
       }
       if (!client.isEnabled()) {
          enableClient(token, client, zone);
       }

       updateClientRoles (token, client.getId(), props.get("roles"), zone);

       return getSecret(token, client.getId(), zone);
    }

    /**
     * get a client, return null if not found
     **/
    private Client getClient (Token token, String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients?clientId=" + clientId;

       StringBuffer error = new StringBuffer();
       Client[] result = this.<Object, Client[]>sendRequest (token, url, HttpMethod.GET, null, Client[].class, zone, true, error);
       if ((error.length()==0) && (result.length > 0)) {
          log.debug ("Client {} found", clientId);
          return result[0];
       } else {
          log.debug ("Client {} not found", clientId);
          return null;
       }
    }

    /**
     * create client
     **/
    private void doCreateClient(Token token, String clientId, Map<String, AbstractPropertyValue> props, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients";
       Client client = new Client();
       client.setClientId(clientId);
       client.setEnabled(true);
       client.setRootUrl(PropertyUtil.getScalarValue(props.get("rootUrl")));
       client.setBaseUrl(PropertyUtil.getScalarValue(props.get("baseUrl")));
       client.setAdminUrl(PropertyUtil.getScalarValue(props.get("adminUrl")));
       String accessType = PropertyUtil.getScalarValue(props.get("accessType"));
       if ((accessType == null) || accessType.equals("public")) {
          client.setPublicClient(true);
       } else {
          client.setPublicClient(false);
       }
       List<Object> oRedirs = ((ListPropertyValue)props.get("validRedirectUris")).getValue();
       List<String> sRedirs = oRedirs.stream()
                                     .map(object -> (String)object)
                                     .collect(Collectors.toList());
       client.setRedirectUris(sRedirs);
       List<Object> oWebOs = ((ListPropertyValue)props.get("webOrigins")).getValue();
       List<String> sWebOs = oWebOs.stream()
                                     .map(object -> (String)object)
                                     .collect(Collectors.toList());
       client.setWebOrigins(sWebOs);

       StringBuffer error = new StringBuffer();
       String result = this.<Client,String>sendRequest (token, url, HttpMethod.POST, client, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Client {} created", clientId);
       } else {
          log.error ("Cannot create client {}", clientId);
       }
    }

    private Role mapClientRole (Map props) {
       Role result = new Role ((String)props.get("name"), (String)props.get("description"), null);
       if (props.get("attributes") != null) {
          List lAttribs = (List)props.get("attributes");
          if (lAttribs.size() > 0) {
             Map<String,List<String>> attribs = new HashMap<String,List<String>>();
             for (Object oAttrib : lAttribs) {
                Map<String,String> mAttrib = (Map<String,String>) oAttrib;
                List<String> vals = new ArrayList<String>();
                vals.add (mAttrib.get("value"));
                attribs.put (mAttrib.get("name"),vals);
             }
             result.setAttributes(attribs);
          }
       }
       try {
          log.debug ("Client role to create: {}", mapper.writeValueAsString(result));
       } catch (Exception e) {}
       return result;
    }

    /**
     * Update client roles
     **/
    private void updateClientRoles (Token token, String clientId, AbstractPropertyValue rolePV, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");

       /* get existing roles */
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles";

       StringBuffer error = new StringBuffer();
       Role[] existingRoles = this.<Object, Role[]>sendRequest (token, url, HttpMethod.GET, null, Role[].class, zone, true, error);
       if (error.length()!=0) {
          log.debug ("Cannot get roles for client {}", clientId);
          return;
       }
       List<Role> existingRolesList = Arrays.asList(existingRoles);

       List<Object> oRoles = null;
       if (rolePV != null) {
          oRoles = ((ListPropertyValue)rolePV).getValue();
       }
       List<Role> newRoles = safe(oRoles).stream()
                                   .map(object -> mapClientRole((Map)object))
                                   .collect(Collectors.toList());

       /* delete obsolete roles */
       safe(existingRolesList).forEach ((role) -> {
          if (!newRoles.contains(role)) {
             deleteClientRole (token, role.getName(), clientId, zone);
          }
       });
       /* create new roles */
       safe(newRoles).forEach ((role) -> {
          if (!existingRolesList.contains(role)) {
             createClientRole (token, role, clientId, zone);
          }
          updateClientRole (token, role, clientId, zone);
       });
    }

    /**
     * Delete client role
     **/
    private void deleteClientRole (Token token, String role, String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");

       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles/" + role;
       log.debug ("Deleting client role {}", role);

       StringBuffer error = new StringBuffer();
       String result = this.<Object, String>sendRequest (token, url, HttpMethod.DELETE, null, String.class, zone, true, error);
       if (error.length()!=0) {
          log.debug ("Cannot delete role {} for client {}", role, clientId);
       }
    }

    /**
     * Create client role
     **/
    private void createClientRole (Token token, Role role, String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");

       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles";
       log.debug ("Creating client role {}", role.getName());

       StringBuffer error = new StringBuffer();
       String result = this.<Role, String>sendRequest (token, url, HttpMethod.POST, role, String.class, zone, true, error);
       if (error.length()!=0) {
          log.error ("Cannot create role {} for client {}", role.getName(), clientId);
          return;
       }
    }
     
    /**
     * Update client role
     **/
    private void updateClientRole (Token token, Role role, String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");

       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles/";
       if (role.getAttributes() != null) {
          log.debug ("Updating client role {}", role.getName());
          StringBuffer error = new StringBuffer();
          url = url + role.getName();
          String result = this.<Role, String>sendRequest (token, url, HttpMethod.PUT, role, String.class, zone, true, error);
          if (error.length()==0) {
             log.debug ("Client role {} updated", role.getName());
          } else {
             log.error ("Cannot update client role {}", role.getName());
          }
       }

    }

    /**
     * enable client
     **/
    private void enableClient (Token token, Client client, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");

       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + client.getId();

       StringBuffer error = new StringBuffer();
       client.setEnabled(true);
       String result = this.<Client, String>sendRequest (token, url, HttpMethod.PUT, client, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Client {} enabled", client.getClientId());
       } else {
          log.error ("Cannot enable client {}", client.getClientId());
       }
    }

    /**
     * disable client
     **/
    private void disableClient (String clientId, String zone) {
       Token token = getToken(zone);

       if ((token == null) || StringUtils.isBlank(token.getAccessToken())) {
          log.error ("No token, cannot perform");
          return;
       }

       Client client = getClient(token, clientId, zone);
       if (client == null) {
          log.error ("Cannot find client {}", clientId);
          return;
       }

       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");

       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + client.getId();

       StringBuffer error = new StringBuffer();
       client.setEnabled(false);
       String result = this.<Client, String>sendRequest (token, url, HttpMethod.PUT, client, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Client {} disabled", client.getClientId());
       } else {
          log.error ("Cannot disable client {}", clientId);
       }
    }

    /**
     * get client secret for given client 
     **/
    public String getSecretFromClientId (Token token, String clientName, String zone) {
       Client client = getClient (token, clientName, zone);
       if (client == null) {
          log.error ("Can not find client {}", clientName);
          return null;
       }
       return getSecret (token, client.getId(), zone);
    }

    /**
     * get client secret
     **/
    private String getSecret (Token token, String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/client-secret";

       StringBuffer error = new StringBuffer();
       Secret result = this.<Object, Secret>sendRequest (token, url, HttpMethod.GET, null, Secret.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("secret: {}", result.getValue());
          return result.getValue();
       } else {
          log.debug ("Secret not found");
          return "";
       }
    }

    /**
     * send a request to keycloak
     * T is input data type (for POST/PUT)
     * R is response type
     * data is input data (null for GET)
     * clazz must be class of R
     * in case of error err buffer contains error message
     * if error 401 is received, retries once to get a token
     **/
    private <T,R> R sendRequest (Token token, String url, HttpMethod method, T data, Class clazz, String zone, boolean first, StringBuffer err) {
       RestTemplate restTemplate = null;
       try {
          restTemplate = getRestTemplate();
       } catch (Exception e) {
          log.error ("Error creating restTemplate: {}", e.getMessage());
          err.append(e.getMessage());
          return null;
       }

       HttpHeaders headers = new HttpHeaders();
       headers.set("Authorization", "Bearer " + token.getAccessToken());
       try {
          HttpEntity<T> request;
          if (data != null) {
             request = new HttpEntity (data, headers);
          } else {
             request = new HttpEntity (headers);
          }
          ResponseEntity<R> result = restTemplate.exchange(url, method, request, clazz);
          return result.getBody();
       } catch (HttpClientErrorException he) {
          if ((he.getStatusCode() == HttpStatus.UNAUTHORIZED) && first)
          {
             log.debug ("Token expired, trying again...");
             tokens.remove(zone);
             token = getToken(zone);
             if ((token != null) && !StringUtils.isBlank(token.getAccessToken())) {
                tokens.put (zone, token);
                return sendRequest (token, url, method, data, clazz, zone, false, err);
             }
          }
          log.warn ("{} {} => HTTP error {}", method, url, he.getStatusCode());
          err.append("HTTP error: " + he.getStatusCode());
       } catch (HttpServerErrorException he) {
          log.error ("{} {} => HTTP error {}", method, url, he.getStatusCode());
          err.append("HTTP error: " + he.getStatusCode());
       } catch (ResourceAccessException re) {
          log.error  ("Cannot send request: {}", re.getMessage());
          err.append(re.getMessage());
       }
       return null;
    }


    /**
     * get keycloak token for A4C client id for one zone
     */
    private Token getToken(String zone) {
       Token token = tokens.get(zone);
       if ((token != null) && !StringUtils.isBlank(token.getAccessToken())) {
          return token;
       }
       token = getToken (zone, portalConfiguration.getParameter (zone, "clientId"), getA4CClientSecret(zone));
       tokens.put(zone, token);
       return token;
    }

    /**
     * get keycloak token for given client id for one zone
     */
    public Token getToken (String zone, String clientId, String secret) {
       RestTemplate restTemplate = null;
       try {
          restTemplate = getRestTemplate();
       } catch (Exception e) {
          log.error ("Error creating restTemplate: {}", e.getMessage());
          return null;
       }

       Token token = null;
       String baseUrl = portalConfiguration.getParameter (zone, "iamApiUrl");
       String openidUri = portalConfiguration.getParameter (zone, "openidUri");

       HttpHeaders headers = new HttpHeaders();
       headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
       MultiValueMap<String, String> map= new LinkedMultiValueMap<String, String>();
       map.add("username", portalConfiguration.getParameter (zone, "user"));
       map.add("password", portalConfiguration.getParameter (zone, "password"));
       map.add("client_id", clientId);
       if ((secret != null) && !secret.trim().equals("")) {
          map.add("client_secret", secret);
       }
       map.add("grant_type", "password");

       HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);
       try {
          token = restTemplate.postForObject(baseUrl+openidUri+"/token", request, Token.class);
          log.debug("Token {}", token.getAccessToken());
       } catch (HttpClientErrorException he) { 
          log.error ("Cannot get token: HTTP error {}", he.getStatusCode());
       } catch (HttpServerErrorException he) { 
          log.error ("Cannot get token: HTTP error {}", he.getStatusCode());
       } catch (ResourceAccessException re) {
          log.error  ("Cannot get token: {}", re.getMessage());
       }
       return token;
    }

    /**
     * initialise rest without checking certificate
     **/
    private RestTemplate getRestTemplate() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        TrustStrategy acceptingTrustStrategy = new TrustStrategy() {
            @Override
            public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                return true;
            }
        };
        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null,acceptingTrustStrategy).build();
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
    }
 
}
