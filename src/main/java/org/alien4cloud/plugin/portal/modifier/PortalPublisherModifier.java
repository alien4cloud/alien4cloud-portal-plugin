package org.alien4cloud.plugin.portal.modifier;

import alien4cloud.common.MetaPropertiesService;
import alien4cloud.model.common.Tag;
import alien4cloud.model.common.MetaPropertyTarget;
import alien4cloud.paas.wf.validation.WorkflowValidator;
import alien4cloud.tosca.context.ToscaContextual;
import static alien4cloud.utils.AlienUtils.safe;
import alien4cloud.utils.PropertyUtil;

import lombok.extern.slf4j.Slf4j;
import org.alien4cloud.alm.deployment.configuration.flow.EnvironmentContext;
import org.alien4cloud.alm.deployment.configuration.flow.FlowExecutionContext;
import org.alien4cloud.alm.deployment.configuration.flow.TopologyModifierSupport;

import org.alien4cloud.tosca.model.CSARDependency;
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

import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBE_CLUSTER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.NAMESPACE_RESOURCE_NAME;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_DEPLOYMENT_RESOURCE;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SERVICE_RESOURCE;

import org.alien4cloud.plugin.portal.configuration.*;
import static org.alien4cloud.plugin.portal.PortalConstants.*;
import static org.alien4cloud.plugin.portal.csar.Version.PORTALPLUGIN_CSAR_VERSION;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Resource;
import javax.inject.Inject;

@Slf4j
@Component("portal-publisher")
public class PortalPublisherModifier extends TopologyModifierSupport {

    @Resource
    protected PortalConsulConfiguration consulConfiguration;
    @Resource
    protected PortalPortalConfiguration portalConfiguration;

    @Resource
    private MetaPropertiesService metaPropertiesService;

    private final ObjectMapper mapper = new ObjectMapper();
 
    private List<String> parameters = Stream.of ("iamBaseUrl", "smdUrl", "smdUser",
                                       "smdPassword", "portalClient",
                                       "portalSecret", "portalBaseUrl",
                                       "replicaCount", "proxyBaseUrl",
                                       "proxyHost", "dnsResolver",
                                       "zoneNamespace", "imageUrl",
                                       "ingressClass").collect(Collectors.toList());

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
        /* get zone from namespace resource */
        NodeTemplate kubeNS = topology.getNodeTemplates().get((String)context.getExecutionCache().get(NAMESPACE_RESOURCE_NAME));
        if (kubeNS != null) {
           try {
              ObjectNode spec = (ObjectNode) mapper.readTree(PropertyUtil.getScalarValue(kubeNS.getProperties().get("resource_spec")));
              zone = spec.with("metadata").with("labels").get("ns-zone-de-sensibilite").textValue();
           } catch(Exception e) {
              log.info("Can't find ns-zone-de-sensibilite");
           }
        } else {
           log.info ("No namespace resource");
        }
        if (StringUtils.isBlank(zone)) {
           log.info ("Zone not set, can not perform");
           return;
        }

        /* get initial topology */
        Topology init_topology = (Topology)context.getExecutionCache().get(FlowExecutionContext.INITIAL_TOPOLOGY);

        String kubeConfig = null;
        Set<NodeTemplate> kubeClusterNodes = TopologyNavigationUtil.getNodesOfType(init_topology, K8S_TYPES_KUBE_CLUSTER, false);
        if (kubeClusterNodes != null && !kubeClusterNodes.isEmpty()) {
            if (kubeClusterNodes.size() > 1) {
                context.log().warn("More than one KubeCluster node have been found, just taking the first one");
            }
            NodeTemplate kubeClusterNode = kubeClusterNodes.iterator().next();
            AbstractPropertyValue configPV = PropertyUtil.getPropertyValueFromPath(kubeClusterNode.getProperties(), "config");
            if (configPV != null && configPV instanceof ScalarPropertyValue) {
                kubeConfig = ((ScalarPropertyValue)configPV).getValue();
            }
        }
 
        if (StringUtils.isBlank(kubeConfig)) {
           log.info ("K8S config not set, can not perform");
           return;
        }

        /* get "Cas d'usage" from initial topology meta property */
        String cuname = null;
        String cuNameMetaPropertyKey = this.metaPropertiesService.getMetapropertykeyByName(CUNAME_PROP, MetaPropertyTarget.APPLICATION);

        if (cuNameMetaPropertyKey != null) {
           Optional<EnvironmentContext> ec = context.getEnvironmentContext();
           if (ec.isPresent() && cuNameMetaPropertyKey != null) {
              EnvironmentContext env = ec.get();
              Map<String, String> metaProperties = safe(env.getApplication().getMetaProperties());
              String sCuname = metaProperties.get(cuNameMetaPropertyKey);
              if (StringUtils.isNotBlank(sCuname)) {
                  cuname = sCuname;
              }
          }
        }
        if (cuname == null) {
           log.warn( "Can not find {}", CUNAME_PROP);
           cuname = "default";
        }

        /* proxied services and corresponding service resource nodes */
        Set<NodeTemplate> services = TopologyNavigationUtil.getNodesOfType(init_topology, PROXIED_SERVICE, true);
        Set<NodeTemplate> kubeSRnodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_SERVICE_RESOURCE, true);

        for (NodeTemplate node : services) {
           log.info("Processing node {}", node.getName());

           /* get node in final topology corresponding to node in initial topology */
           NodeTemplate kubeSRnode = null;

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
           String upstreamUrl = PropertyUtil.getScalarValue(kubeSRnode.getProperties().get("cluster_url"));

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

           /* get useful properties from service endpoint */
           Capability endpoint = safe(node.getCapabilities()).get("service_endpoint");
           if (endpoint == null) {
              log.warn ("No service_endpoint for {}, skip it", node.getName());
              continue;
           }
           String url_path = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("url_path"));
           String description = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("description"));
           String locationOptions = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("locationOptions"));

           String url = getParameter (zone, "proxyBaseUrl") + url_path;

           /* --- Consul --- */

           /* add a node (to final topology) which will publish info to consul */
           String nodeName = String.format("%s_Consul",node.getName());
           NodeTemplate csnode = addNodeTemplate(null,topology,nodeName, CONSUL_RUNNER, getCsarVersion(init_topology));

           /* set consul url and optionally key/certificate (file names on orchestrator machine) */
           String consulUrl = consulConfiguration.getUrl();
           if ((consulUrl == null) || consulUrl.equals("")) {
              consulUrl = "http://localhost:8500";
           }
           setNodePropertyPathValue(null,topology,csnode,"url", new ScalarPropertyValue(consulUrl));
           if ( (consulConfiguration.getCertificate() != null) && (consulConfiguration.getKey() != null) ) {
              setNodePropertyPathValue(null,topology,csnode,"certificate", new ScalarPropertyValue(consulConfiguration.getCertificate()));
              setNodePropertyPathValue(null,topology,csnode,"key", new ScalarPropertyValue(consulConfiguration.getKey()));
           }
           String name = cuname + "/" + qualifiedName;
           setNodePropertyPathValue(null,topology,csnode,"name", new ScalarPropertyValue(name));

           /* data to be published into consul */
           ConsulData data = new ConsulData();

           data.setName(description);
           data.setAdmin(Boolean.valueOf(PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("admin"))));
           data.setQualifiedName(qualifiedName);
           data.setDescription(description);
           data.setLogo("/logo.png");
           data.setLogo(PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("logo")));
           data.setDeploymentDate ( (new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss")).format(new Date()).toString() );
           data.setType (PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("service_type")));
           data.setUrl(url);
           data.setUpstreamUrl(upstreamUrl);
           data.setZone(zone);

           try {
              setNodePropertyPathValue(null,topology,csnode,"data", new ScalarPropertyValue(mapper.writeValueAsString(data)));
           } catch (Exception e) {
              log.warn("Couldn't set data", e);
           }

           /* add relationship on target node so as to be run after the node is deployed */
           addRelationshipTemplate (null, topology, csnode, kubeSRnode.getName(), NormativeRelationshipConstants.DEPENDS_ON,
                     "dependency", "feature");

           /* --- ReverseProxyConfigurator --- */

           /** look for associated deployment resource: 
            *  module is hosted on KubeDeployment
            *  look for deploymlent resource associated with this KubeDeployment
            **/
           NodeTemplate deployment = TopologyNavigationUtil.getImmediateHostTemplate(init_topology, module);
           NodeTemplate kubeDRnode = null;
           Set<NodeTemplate> kubeDRnodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_DEPLOYMENT_RESOURCE, true);
           for (NodeTemplate knode : kubeDRnodes) {
              String initialNodeName  = TopologyModifierSupport.getNodeTagValueOrNull(knode, A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR);
              if ( (initialNodeName != null) && initialNodeName.equals(deployment.getName()) ) { 
                 kubeDRnode = knode;
                 break;
              }
           }
           if (kubeDRnode == null) {
              log.warn ("No DeploymentResource for node {}, can not add ReverseProxyConfigurator", deployment.getName());
              continue;
           }

           /* add a node (to final topology) which will create K8S resources for reverse proxy */
           nodeName = String.format("%s_RP",module.getName());
           NodeTemplate rpnode = addNodeTemplate(null,topology,nodeName, RP_CONFIGURATOR, getCsarVersion(init_topology));

           /* set PD & ZD properties */
           for (String param : parameters) {
              setNodePropertyPathValue(null,topology,rpnode,param,new ScalarPropertyValue(getParameter(zone,param))); 
           }

           /* set UD properties */ 
           if (!StringUtils.isBlank(url_path)) {
              setNodePropertyPathValue(null,topology,rpnode,"contextPath", new ScalarPropertyValue(url_path));
           }
           setNodePropertyPathValue(null,topology,rpnode,"serviceUpstreamUrl", new ScalarPropertyValue(upstreamUrl));
           String uc_id = context.getEnvironmentContext().get().getApplication().getId() + "-" + 
                          context.getEnvironmentContext().get().getEnvironment().getName() + "-" +
                          module.getName();
           setNodePropertyPathValue(null,topology,rpnode,"uc_id", new ScalarPropertyValue(uc_id.toLowerCase().replaceAll("_","-")));
           setNodePropertyPathValue(null,topology,rpnode,"kubeConfig", new ScalarPropertyValue(kubeConfig));
           if (!StringUtils.isBlank(locationOptions)) {
              setNodePropertyPathValue(null,topology,rpnode,"locationOptions", new ScalarPropertyValue(locationOptions));
           }

           /* add relationship on target node so as to be run after the node is deployed */
           addRelationshipTemplate (null, topology, rpnode, kubeDRnode.getName(), NormativeRelationshipConstants.DEPENDS_ON,
                     "dependency", "feature");
        }

    }

    private final String getCsarVersion(Topology topology) {
        return getCsarVersion(topology,"org.alien4cloud.portalplugin");
    }

    private final  String getCsarVersion(Topology topology,String archiveName) {
        for (CSARDependency dep : topology.getDependencies()) {
            if (dep.getName().equals(archiveName)) {
                return dep.getVersion();
            }
        }
        return PORTALPLUGIN_CSAR_VERSION;
    }

    /**
     * look for a configuration parameter:
     *   - as a ZD parameter
     *   - if not set, as a PD parameter
     **/
    private String getParameter (String zone, String parameter) {
       String result = safe(safe(portalConfiguration.getZones()).get(zone)).get(parameter);
       log.debug ("Parameter {} ({}): {}", parameter, zone, result);
       if (StringUtils.isBlank(result)) {
          result = safe(portalConfiguration.getAll()).get(parameter);
          log.debug ("Parameter {} (ALL): {}", parameter, result);
       }
       if (result == null) {
          result = "";
       }
       return result;
    }

    @Getter
    @Setter
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private class ConsulData {
        private String name; 
        private String qualifiedName; 
        private String description; 
        private String type; 
        private boolean active = true; 
        private String logo; 
        private String deploymentDate; 
        private boolean admin;
        private String url;
        private String upstreamUrl;
        private String zone;
    }
}
