package org.alien4cloud.plugin.portal.modifier;

import alien4cloud.model.common.Tag;
import alien4cloud.paas.wf.validation.WorkflowValidator;
import alien4cloud.tosca.context.ToscaContextual;
import static alien4cloud.utils.AlienUtils.safe;
import alien4cloud.utils.PropertyUtil;

import org.alien4cloud.alm.deployment.configuration.flow.EnvironmentContext;
import org.alien4cloud.alm.deployment.configuration.flow.FlowExecutionContext;
import org.alien4cloud.alm.deployment.configuration.flow.TopologyModifierSupport;

import org.alien4cloud.tosca.model.definitions.ComplexPropertyValue;
import org.alien4cloud.tosca.model.definitions.ScalarPropertyValue;
import org.alien4cloud.tosca.model.templates.Capability;
import org.alien4cloud.tosca.model.templates.NodeTemplate;
import org.alien4cloud.tosca.model.templates.RelationshipTemplate;
import org.alien4cloud.tosca.model.templates.Topology;
import org.alien4cloud.tosca.utils.TopologyNavigationUtil;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import lombok.extern.slf4j.Slf4j;

import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBE_NAMESPACE;

import org.alien4cloud.plugin.portal.configuration.PortalPortalConfiguration;
import org.alien4cloud.plugin.portal.model.*;
import static org.alien4cloud.plugin.portal.PortalConstants.IAM_RELATION;
import static org.alien4cloud.plugin.portal.PortalConstants.IAM_TYPE;
import static org.alien4cloud.plugin.portal.PortalConstants.PROXIED_SERVICE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Resource;

@Slf4j
@Component("iam-manager")
public class IAMManagerModifier extends TopologyModifierSupport {

    @Resource
    protected PortalPortalConfiguration portalConfiguration;

    private Token token = null;

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
           /* get url_path property from service endpoint */
           Capability endpoint = safe(node.getCapabilities()).get("service_endpoint");
           if (endpoint == null) {
              log.warn ("No service_endpoint for {}, skip it", node.getName());
              continue;
           }

           /* set proxied_url property for services */
           String url_path = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("url_path"));
           if (url_path == null) {
              url_path = "";
           }
           String url = portalConfiguration.getParameter (zone, "proxyBaseUrl") + url_path;
           endpoint.getProperties().put("proxied_url", new ScalarPropertyValue(url));

           /*--- create IAM role ---*/

           /* get module qualified name */
           Set<RelationshipTemplate> rels = TopologyNavigationUtil.getTargetRelationships(node, "expose");
           if (rels.size() == 0) {
               log.warn ("No 'expose' relation for {}, skip it", node.getName());
               continue;
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
              continue;
           }
           log.debug("Module qualifiedName: {}", qualifiedName);

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
           String tabname = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("portalTabname"));
           if (StringUtils.isBlank(tabname)) {
              log.info ("Tab name not set for {}, using 'cas-usage'", node.getName());
              tabname = "cas-usage";
           }

           if (!createRole (qualifiedName, tabname, zone)) {
              context.log().warn("Can not create role {}_casusage_role", qualifiedName);
           }
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
           endpoint.getProperties().put("proxyHost", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "proxyHost")));
           endpoint.getProperties().put("portalExternalUrl", new ScalarPropertyValue(portalConfiguration.getParameter(zone, "portalExternalUrl")));

           String clientId = PropertyUtil.getScalarValue(endpoint.getProperties().get("clientId"));

           String clientSecret = createClient (clientId, zone);

           if (clientSecret.equals("")) {
              context.log().warn("Can not get client secret for {}", clientId);
           }

           endpoint.getProperties().put("clientSecret", new ScalarPropertyValue(clientSecret));
        }
    }

    /**
     * create role in keycloak if it does not exist yet, return false if error 
     **/
    private boolean createRole (String qualifiedName, String tabname, String zone) {
       getToken(zone);

       if ((token == null) || StringUtils.isBlank(token.getAccessToken())) {
          log.error ("No token, cannot perform");
          return false;
       }

       if (!existRole(qualifiedName, zone)) {
          return doCreateRole (qualifiedName, tabname, zone);
       }

       return true;
    }

    /**
     * test whether a role exists or not
     **/
    private boolean existRole (String name, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamBaseUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/roles/" + name + "_casusage_role";

       StringBuffer error = new StringBuffer();
       Role result = this.<Object, Role>sendRequest (url, HttpMethod.GET, null, Role.class, zone, true, error);
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
    private boolean doCreateRole(String name, String tabname, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamBaseUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/roles";
       name = name + "_casusage_role";

       Role role = new Role();
       role.setName(name);
       role.setDescription ("Artemis role '" + name + "'");
       ArrayList tabs = new ArrayList();
       tabs.add(tabname);
       HashMap<String,List<String>> attrs = new HashMap<String,List<String>>();
       attrs.put ("tabname", tabs);
       role.setAttributes(attrs);

       /* create role */
       StringBuffer error = new StringBuffer();
       String result = this.<Role, String>sendRequest (url, HttpMethod.POST, role, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Role {} created", name);
       } else {
          log.error ("Cannot create role {}", name);
          return false;
       }

       /* update role (to set tabname) */
       error = new StringBuffer();
       url = url + "/" + name;
       result = this.<Role, String>sendRequest (url, HttpMethod.PUT, role, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Role {} updated", name);
       } else {
          log.error ("Cannot update role {}", name);
          return false;
       }
       return true;
    }

    /**
     * create client in keycloak if it does not exist yet, return client secret 
     **/
    private String createClient (String clientId, String zone) {
       getToken(zone);

       if ((token == null) || StringUtils.isBlank(token.getAccessToken())) {
          log.error ("No token, cannot perform");
          return "";
       }

       Client client = getClient(clientId, zone);
       if (client == null) {
          doCreateClient(clientId, zone);
          client = getClient(clientId, zone);
       }
       if (client == null)
       {
          return "";
       }
       return getSecret(client.getId(), zone);
    }

    /**
     * get a client, return null if not found
     **/
    private Client getClient (String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamBaseUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients?clientId=" + clientId;

       StringBuffer error = new StringBuffer();
       Client[] result = this.<Object, Client[]>sendRequest (url, HttpMethod.GET, null, Client[].class, zone, true, error);
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
    private void doCreateClient(String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamBaseUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients";
       Client client = new Client();
       client.setClientId(clientId);

       StringBuffer error = new StringBuffer();
       String result = this.<Client,String>sendRequest (url, HttpMethod.POST, client, String.class, zone, true, error);
       if (error.length()==0) {
          log.debug ("Client {} created", clientId);
       } else {
          log.error ("Cannot create client {}", clientId);
       }
    }

    /**
     * get client secret
     **/
    private String getSecret (String clientId, String zone) {
       String baseUrl = portalConfiguration.getParameter (zone, "iamBaseUrl");
       String realm = portalConfiguration.getParameter (zone, "realm");
       String url = baseUrl + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/client-secret";

       StringBuffer error = new StringBuffer();
       Secret result = this.<Object, Secret>sendRequest (url, HttpMethod.GET, null, Secret.class, zone, true, error);
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
    private <T,R> R sendRequest (String url, HttpMethod method, T data, Class clazz, String zone, boolean first, StringBuffer err) {
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
             token = null;
             getToken(zone);
             if ((token != null) && !StringUtils.isBlank(token.getAccessToken())) {
                return sendRequest (url, method, data, clazz, zone, false, err);
             }
          }
          log.warn ("{} {} => HTTP error {}", method, url, he.getStatusCode());
          err.append("HTTP error: " + he.getStatusCode());
       } catch (ResourceAccessException re) {
          log.error  ("Cannot send request: {}", re.getMessage());
          err.append(re.getMessage());
       }
       return null;
    }


    /**
     * get keycloak token for further use
     */
    private void getToken(String zone) {
       if ((token != null) && !StringUtils.isBlank(token.getAccessToken())) {
          return;
       }

       RestTemplate restTemplate = null;
       try {
          restTemplate = getRestTemplate();
       } catch (Exception e) {
          log.error ("Error creating restTemplate: {}", e.getMessage());
          return;
       }

       String baseUrl = portalConfiguration.getParameter (zone, "iamBaseUrl");
       String openidUri = portalConfiguration.getParameter (zone, "openidUri");

       HttpHeaders headers = new HttpHeaders();
       headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
       MultiValueMap<String, String> map= new LinkedMultiValueMap<String, String>();
       map.add("username", portalConfiguration.getParameter (zone, "user"));
       map.add("password", portalConfiguration.getParameter (zone, "password"));
       map.add("client_id", portalConfiguration.getParameter (zone, "clientId"));
       map.add("client_secret", portalConfiguration.getParameter (zone, "clientSecret"));
       map.add("grant_type", "password");

       HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);
       try {
          token = restTemplate.postForObject(baseUrl+openidUri+"/token", request, Token.class);
          log.debug("Token {}", token.getAccessToken());
       } catch (HttpClientErrorException he) { 
          log.error ("Cannot get token: HTTP error {}", he.getStatusCode());
       } catch (ResourceAccessException re) {
          log.error  ("Cannot get token: {}", re.getMessage());
       }
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
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
    }
 
}
