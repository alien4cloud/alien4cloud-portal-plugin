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
import alien4cloud.tosca.context.ToscaContext;
import static alien4cloud.utils.AlienUtils.safe;
import alien4cloud.utils.PropertyUtil;

import org.alien4cloud.alm.deployment.configuration.flow.TopologyModifierSupport;

import org.alien4cloud.tosca.model.definitions.AbstractPropertyValue;
import org.alien4cloud.tosca.model.definitions.ScalarPropertyValue;
import org.alien4cloud.tosca.model.templates.Capability;
import org.alien4cloud.tosca.model.templates.NodeTemplate;
import org.alien4cloud.tosca.model.templates.RelationshipTemplate;
import org.alien4cloud.tosca.model.templates.Topology;
import org.alien4cloud.tosca.normative.constants.NormativeRelationshipConstants;
import org.alien4cloud.tosca.utils.TopologyNavigationUtil;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBE_CLUSTER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.NAMESPACE_RESOURCE_NAME;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SERVICE_RESOURCE;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SIMPLE_RESOURCE;

import org.alien4cloud.plugin.portal.configuration.*;
import org.alien4cloud.plugin.portal.model.ImportApiRequest;
import static org.alien4cloud.plugin.portal.PortalConstants.*;

import lombok.extern.slf4j.Slf4j;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.annotation.Resource;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;

@Slf4j
@Component("apigw-publisher")
public class ApiGwPublisherModifier {

    @Resource
    protected PortalPortalConfiguration configuration;

    private final ObjectMapper mapper = new ObjectMapper();
 
    @Inject
    private IPaasEventService eventService;
    @Inject
    private DeploymentRuntimeStateService deploymentRuntimeStateService;
    @Inject
    private DeploymentService deploymentService;

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
            case DEPLOYED:
                processDeployment (deployment, HttpMethod.POST);
                break;
            case UNDEPLOYED:
                processDeployment (deployment, HttpMethod.DELETE);
                break;
            default:
                return;
        }
    }

    private void processDeployment (Deployment deployment, HttpMethod method) {
        log.info ("Processing deployment " + deployment.getId());
        DeploymentTopology deployedTopology = deploymentRuntimeStateService.getRuntimeTopology(deployment.getId());
        if (deployedTopology == null) {
            log.error("Deployed topology is no longer available.");
            return;
        }

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
        Topology initialTopology = deploymentRuntimeStateService.getUnprocessedTopology(deployment.getId());

        try {
           ToscaContext.init(deployedTopology.getDependencies());
           sendRequest(deployedTopology, initialTopology, zone, method);
        } catch (Exception e) {
            log.warn ("Couldn't process apigw publisher listener", e);
        } finally {
           ToscaContext.destroy();
        }
    }

    private void sendRequest (Topology topology, Topology init_topology, String zone, HttpMethod method) {
        /* api service nodes */
        Set<NodeTemplate> services = TopologyNavigationUtil.getNodesOfType(init_topology, API_SERVICE, true);

        List<ImportApiRequest> request = new ArrayList<ImportApiRequest>();
        for (NodeTemplate node : services) {
           log.info("Processing node {}", node.getName());

           /* get node in final topology corresponding to node in initial topology */
           NodeTemplate kubeSRnode = null;

           Set<NodeTemplate> kubeSRnodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_SERVICE_RESOURCE, true);
           for (NodeTemplate knode : kubeSRnodes) {
              String initialNodeName  = TopologyModifierSupport.getNodeTagValueOrNull(knode, A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR);
              if ( (initialNodeName != null) && initialNodeName.equals(node.getName()) ) { 
                 kubeSRnode = knode;
                 break;
              }
           }
           if (kubeSRnode == null) {
              log.warn ("No ServiceResource for node {} skip it", node.getName());
              continue;
           }
           String baseUrl = PropertyUtil.getScalarValue(kubeSRnode.getProperties().get("cluster_url"));

           /* get qualified name set on module */
           RelationshipTemplate relation = TopologyNavigationUtil.getRelationshipFromType(node, NormativeRelationshipConstants.CONNECTS_TO);
           NodeTemplate module = init_topology.getNodeTemplates().get(relation.getTarget());
           String qualifiedName = "not_set";
           List<Tag> tags = module.getTags();
           for (Tag tag: safe(tags)) {
              if (tag.getName().equals("qualifiedName")) {
                 qualifiedName = tag.getValue();
              }
           }
           if (qualifiedName.equals("not_set")) {
              log.warn ("Cannot find qualified name for {}, skip it", node.getName());
              continue;
           }

           Capability endpoint = safe(node.getCapabilities()).get("service_endpoint");
           if (endpoint == null) {
              log.warn ("No service_endpoint for {}, skip it", node.getName());
              continue;
           }
           String uri = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("suburlspec"));
           ImportApiRequest req = new ImportApiRequest();
           req.setUri(baseUrl + "/" + qualifiedName + "." + node.getName() + uri);
           request.add(req);
        }
        if (!request.isEmpty()) {
           sendRequest (configuration.getParameter (zone, "importApiUrl"), method, request);
        }
    }

    private void sendRequest (String url, HttpMethod method, List<ImportApiRequest> data) {
       RestTemplate restTemplate = null;
       try {
          restTemplate = getRestTemplate();
       } catch (Exception e) {
          log.error ("Error creating restTemplate: {}", e.getMessage());
          return;
       }

       try {
          log.debug ("ImportOpenApi {} request: {}", method, mapper.writeValueAsString(data));
       } catch (Exception e) {}
       try {
          HttpEntity<List<ImportApiRequest>> request;
          request = new HttpEntity (data);
          ResponseEntity<String> resp = restTemplate.exchange(url, method, request, String.class);
          String result = resp.getBody();
          log.debug ("ImportOpenApi {} response: {}", method, result);
          try {
             ObjectNode response = (ObjectNode) mapper.readTree(result);
             String infos = response.get("Infos").textValue();
             log.info("Infos: {}", infos);
             Iterator<String> fields = response.fieldNames();
             while (fields.hasNext()) {
                String field = fields.next();
                if (!field.equals("Infos")) {
                   ObjectNode api = (ObjectNode)response.get(field);
                   int status = api.get("Status").intValue();
                   log.debug ("API: {}, status: {}", field, status);
                   if (status != 200) {
                      log.warn("Status = {} for {} {}", status, method, field);
                   }
                }
             }
          } catch (Exception e) {
             log.error ("Cannot decode importopenapi response: {}", result);
          }
       } catch (HttpClientErrorException he) {
          log.error ("HTTP error {}", he.getStatusCode());
       } catch (HttpServerErrorException he) {
          log.error ("HTTP error {}", he.getStatusCode());
       } catch (ResourceAccessException re) {
          log.error  ("Cannot send request: {}", re.getMessage());
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
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
    }
}
