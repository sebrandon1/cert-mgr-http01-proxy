package utils

import (
	"bytes"
	"certmgrhttp01proxy/templates"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func NewReverseProxy(targetURL string) (*httputil.ReverseProxy, error) {
	// Parse targetURL (backend server URL)
	url, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Create proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Set original host header
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.Header.Set("Host", req.Host)
		req.Header.Set("X-Proxy-Server", "cert-mgt-http01-proxy")
	}
	// Add Error Handling
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Error handling request: %v\n", err)
		http.Error(w, "Backend unavailable", http.StatusBadGateway)
	}

	// In case Proxy is set, use it
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	return proxy, nil
}

func newKubeClient() (*dynamic.DynamicClient, error) {
	var config *rest.Config
	var err error
	config, err = rest.InClusterConfig()

	//used for localtesting
	//config, err = clientcmd.BuildConfigFromFlags("", "/home/mario/.kubeconfigs/bm-cluster")

	if err != nil {
		return nil, err
	}

	client, err := dynamic.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	return client, err
}

func GetOCPEnvDetails() (apiHostname string, appsVIP string, apiVIP string, platformType string, clusterVersion string, err error) {
	// Get a new kubeClient and query the required objects
	// We need to know API DNS Record and APPS VIP

	client, err := newKubeClient()
	if err != nil {
		return "", "", "", "", "", err
	}
	// Get Platform type, for now we only run on BM
	infrastructureResource := schema.GroupVersionResource{Group: "config.openshift.io", Version: "v1", Resource: "infrastructures"}
	infrastructureData, err := client.Resource(infrastructureResource).Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return "", "", "", "", "", err
	}
	platformType, _, err = unstructured.NestedString(infrastructureData.Object, "status", "platform")
	if err != nil {
		return "", "", "", "", "", err
	}
	// Get Ingress config for the cluster, from this object we can derive API endpoint and apps VIP
	ingressResource := schema.GroupVersionResource{Group: "config.openshift.io", Version: "v1", Resource: "ingresses"}
	ingressData, err := client.Resource(ingressResource).Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return "", "", "", "", "", err
	}
	ingressDomain, _, err := unstructured.NestedString(ingressData.Object, "spec", "domain")
	if err != nil {
		return "", "", "", "", "", err
	}
	// Get ClusterVersion (required since we only support 4.17+)
	clusterVersionResource := schema.GroupVersionResource{Group: "config.openshift.io", Version: "v1", Resource: "clusterversions"}
	clusterVersionData, err := client.Resource(clusterVersionResource).Get(context.TODO(), "version", metav1.GetOptions{})
	if err != nil {
		return "", "", "", "", "", err
	}
	clusterVersion, _, err = unstructured.NestedString(clusterVersionData.Object, "status", "desired", "version")
	if err != nil {
		return "", "", "", "", "", err
	}
	apiHostname = strings.Replace(ingressDomain, "apps", "api", 1)
	// Resolve APPs hostname to get VIP
	ips, err := resolveDNSRecord("test." + ingressDomain)
	// Return only 1 IP in case there are more than 1
	appsVip := ips[0].String()
	if err != nil {
		return "", "", "", "", "", err
	}
	// Resolve API hostname to get VIP
	ips, err = resolveDNSRecord(apiHostname)
	// Return only 1 IP in case there are more than 1
	apiVip := ips[0].String()
	if err != nil {
		return "", "", "", "", "", err
	}

	return apiHostname, appsVip, apiVip, platformType, clusterVersion, nil
}

func CreateNFTablesRuleMachineConfig(apiVIP string, port string) error {
	// https://access.redhat.com/articles/7090422

	data := templates.TemplateData{
		ApiVIP:    apiVIP,
		ProxyPort: port,
		NFTRules:  "",
	}
	tmpl, err := template.New("nftables").Parse(templates.NFTRuleTemplate)
	if err != nil {
		return err
	}
	var nfttablesResult bytes.Buffer
	if err := tmpl.Execute(&nfttablesResult, data); err != nil {
		return err
	}
	// Assign NFTRules value
	data.NFTRules = base64.StdEncoding.EncodeToString(nfttablesResult.Bytes())

	tmpl, err = template.New("machineconfig").Parse(templates.MachineConfig)
	if err != nil {
		return err
	}
	var machineConfigResult bytes.Buffer
	if err := tmpl.Execute(&machineConfigResult, data); err != nil {
		return err
	}

	// Create MachineConfiguration and MachineConfig
	client, err := newKubeClient()
	if err != nil {
		return err
	}
	obj := &unstructured.Unstructured{}
	decoder := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)

	// MachineConfiguration
	_, _, err = decoder.Decode(bytes.NewBufferString(templates.MachineConfiguration).Bytes(), nil, obj)
	if err != nil {
		return err
	}
	gvr := schema.GroupVersionResource{
		Group:    "operator.openshift.io",
		Version:  "v1",
		Resource: "machineconfigurations",
	}
	objData, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	_, err = client.Resource(gvr).Patch(
		context.TODO(),
		obj.GetName(),
		types.ApplyPatchType,
		objData,
		metav1.PatchOptions{FieldManager: "cert-mgr-htt01-proxy"},
	)
	if err != nil {
		return err
	}

	// MachineConfig
	_, _, err = decoder.Decode(machineConfigResult.Bytes(), nil, obj)
	if err != nil {
		return err
	}
	gvr = schema.GroupVersionResource{
		Group:    "machineconfiguration.openshift.io",
		Version:  "v1",
		Resource: "machineconfigs",
	}

	objData, err = json.Marshal(obj)
	if err != nil {
		return err
	}

	_, err = client.Resource(gvr).Patch(
		context.TODO(),
		obj.GetName(),
		types.ApplyPatchType,
		objData,
		metav1.PatchOptions{FieldManager: "cert-mgr-htt01-proxy"},
	)
	if err != nil {
		return err
	}

	return nil
}

func SupportedOCPVersion(runningVersion string) error {
	version := strings.Split(runningVersion, ".")
	if len(version) <= 2 { // We should have something like 4.X.Y.
		return errors.New("Invalid OCP version " + runningVersion + " (expecting X.Y.Z format)")
	}
	major, _ := strconv.Atoi(version[0])
	minor, _ := strconv.Atoi(version[1])
	if major < 4 {
		return errors.New("Unsupported OCP version " + runningVersion + " (minimum supported is 4.17+)")
	}
	if major == 4 && minor < 17 {
		return errors.New("Unsupported OCP version " + runningVersion + " (minimum supported is 4.17+)")
	}
	return nil
}

func resolveDNSRecord(hostname string) (ips []net.IP, err error) {
	var r net.Resolver
	ips, err = r.LookupIP(context.TODO(), "ip", hostname)
	if err != nil {
		return nil, err
	}
	return ips, nil
}
