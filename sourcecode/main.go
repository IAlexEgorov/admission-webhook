package main

import (
	"errors"
	"flag"
	"github.com/rs/zerolog"
	logger "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
	"io"
	v1 "k8s.io/api/apps/v1"
	v12 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"k8s.io/api/admission/v1beta1"

	"encoding/json"
)

type ServerParameters struct {
	port              int    // webhook server port
	certFile          string // path to the x509 certificate for https
	keyFile           string // path to the x509 private key matching `CertFile`
	logLevel          string // level of logging
	programConfigFile string
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type Configuration struct {
	General struct {
		Port        int    `yaml:"port"`
		TLSCertFile string `yaml:"tlsCertFile"`
		TLSKeyFile  string `yaml:"tlsKeyFile"`
		LogLevel    string `yaml:"logLevel"`
	} `yaml:"general"`
	TriggerLabel map[string]string `yaml:"triggerLabel"`
	PatchData    struct {
		Labels      map[string]string `yaml:"labels,omitempty"`
		Annotations map[string]string `yaml:"annotations,omitempty"`
	} `yaml:"patchData"`
}

var parameters ServerParameters

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

var config *rest.Config
var clientSet *kubernetes.Clientset
var programConfigFile Configuration

func main() {

	useKubeConfig := os.Getenv("USE_KUBECONFIG")
	kubeConfigFilePath := os.Getenv("KUBECONFIG")

	flag.IntVar(&parameters.port, "port", 8443, "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.logLevel, "logLevel", "info", "Specify level of logging.")
	flag.StringVar(&parameters.programConfigFile, "config-file", "config.yaml", "Opt for the configuration file.")
	flag.Parse()

	programConfigFile.isConfigurationFileExist(&parameters.programConfigFile)
	selectLogLevel(&parameters.logLevel)

	createConfigFile(useKubeConfig, kubeConfigFilePath)
	logger.Info().Msgf("Starting of API server... \n  Port: %v \t CertFile: %v \t KeyFile: %v \n",
		parameters.port, parameters.certFile, parameters.keyFile)

	http.HandleFunc("/mutate/deployments", HandleMutate)
	err := http.ListenAndServeTLS(":"+strconv.Itoa(parameters.port), parameters.certFile, parameters.keyFile, nil)
	logger.Error().Msg(err.Error())
}

func HandleMutate(w http.ResponseWriter, r *http.Request) {

	// ----------------------------------
	// Receiving of the request from API
	// ----------------------------------
	body, err := io.ReadAll(r.Body)
	logger.Debug().Msg(string(body[:]))

	// -------------------------------------------------
	// Deserialize of JSON from AdmissionReview request
	// and validation of
	// -------------------------------------------------
	var admissionReviewReq v1beta1.AdmissionReview

	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReviewReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Error().Msgf("could not deserialize request: %v", err)
		return
	} else if admissionReviewReq.Request == nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Error().Msg("malformed admission review: request is nil")
		return
	}
	logger.Info().Msgf("Type: %v \t Event: %v \t Name: %v \n",
		admissionReviewReq.Request.Kind,
		admissionReviewReq.Request.Operation,
		admissionReviewReq.Request.Name,
	)

	// -------------------------------------------
	// Creating Deployment object for parsing and
	// analyzing before creating patch data
	// -------------------------------------------
	var statefulset v1.StatefulSet

	err = json.Unmarshal(admissionReviewReq.Request.Object.Raw, &statefulset)
	if err != nil {
		logger.Error().Msgf("could not unmarshal pod on admission request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
	}

	// ---------------------------------------
	// Creating of Patch for Admission Review
	// which will be sent to API server
	// ---------------------------------------
	patches, err := createPatch(&statefulset)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	patchBytes, err := json.Marshal(patches)
	if err != nil {
		logger.Error().Msgf("could not marshal JSON patch: %v", err)
		w.WriteHeader(http.StatusBadRequest)
	}

	admissionReviewResponse := v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID:     admissionReviewReq.Request.UID,
			Allowed: true,
		},
	}
	admissionReviewResponse.Response.Patch = patchBytes

	bytes, err := json.Marshal(&admissionReviewResponse)
	if err != nil {
		logger.Error().Msgf("Marshaling response: %v", err)
		w.WriteHeader(http.StatusBadRequest)
	}

	_, err = w.Write(bytes)
	if err != nil {
		logger.Error().Msgf("Can't send response. Error: '%v'", err)
		return
	}

}

func (c *Configuration) isConfigurationFileExist(configFile *string) {

	//--------------------------------------
	// Check whether --config-file flag was
	// appended or now and if it was, we
	// change global ServerParameters
	//--------------------------------------
	if len(*configFile) == 0 {
		return
	}
	yamlFile, err := os.ReadFile(*configFile)
	if err != nil {
		logger.Error().Msgf("Config file not found: %v", err.Error())
		return
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
		return
	}

	parameters = ServerParameters{
		port:              c.General.Port,
		certFile:          c.General.TLSCertFile,
		keyFile:           c.General.TLSKeyFile,
		logLevel:          c.General.LogLevel,
		programConfigFile: *configFile,
	}
}

func createConfigFile(useKubeConfig string, kubeConfigFilePath string) {

	//---------------------------------------
	// Check if useKubeConfig was not append
	// as ENV variable, we get cluster
	// config by using ServiceAccount of
	// our Admission Webhook pod.
	// If it was, we create it from local
	// kubeconfig path "~/.kube/config"
	//---------------------------------------
	if len(useKubeConfig) == 0 {
		// default to service account in cluster token
		c, err := rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
		config = c
	} else {
		//load from a kube config
		var kubeconfig string

		if kubeConfigFilePath == "" {
			if home := homedir.HomeDir(); home != "" {
				kubeconfig = filepath.Join(home, ".kube", "config")
			}
		} else {
			kubeconfig = kubeConfigFilePath
		}

		logger.Debug().Msg("kubeconfig: " + kubeconfig)

		c, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err.Error())
		}
		config = c
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	clientSet = cs
}

func selectLogLevel(logLevel *string) {
	switch *logLevel {
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func createPatch(statefulset *v1.StatefulSet) ([]patchOperation, error) {

	if programConfigFile.TriggerLabel == nil {
		return nil, errors.New("TriggerLabel is nil")
	}

	var patches []patchOperation

	for labelName, labelVal := range programConfigFile.TriggerLabel {
		for statefulsetLabelName, statefulsetLabelValue := range statefulset.Spec.Template.ObjectMeta.Labels {
			if statefulsetLabelName == labelName {
				if statefulsetLabelValue == labelVal || labelVal == "*" {
					//---------------------
					// Create patch Labels
					//---------------------
					if programConfigFile.PatchData.Labels != nil {
						patches = append(patches, patchOperation{
							Op:    "add",
							Path:  "/spec/template/metadata/labels",
							Value: programConfigFile.PatchData.Labels,
						})
					}

					//--------------------------
					// Create patch Annotations
					//--------------------------
					if programConfigFile.PatchData.Annotations != nil {
						patches = append(patches, patchOperation{
							Op:    "add",
							Path:  "/spec/template/metadata/annotations",
							Value: programConfigFile.PatchData.Annotations,
						})
					}

					//-----------------------------------
					// Create difficult
					// patch data: envFrom, livecycle,
					// volumes, initContainerVolumeMount,
					// initContainers
					//-----------------------------------
					envFrom := v12.EnvFromSource{
						SecretRef: &v12.SecretEnvSource{
							LocalObjectReference: v12.LocalObjectReference{
								Name: "secret",
							},
							Optional: nil,
						},
					}
					livecycle := v12.Lifecycle{
						PostStart: &v12.Handler{
							Exec: &v12.ExecAction{
								Command: []string{"/bin/sh", "-c", "ls -la"},
							},
						},
					}

					volumes := v12.Volume{
						Name: "wasmfilters-dir",
						VolumeSource: v12.VolumeSource{
							EmptyDir: &v12.EmptyDirVolumeSource{},
						},
					}

					initContainerVolumeMount := v12.VolumeMount{
						Name:      "wasmfilters-dir",
						MountPath: "/var/local/lib/wasm-filters",
					}

					initContainers := v12.Container{
						Name:         "mlflow-tracking-webassembly",
						Image:        "nexus.do.neoflex.ru/webassembly:1.0.2",
						Command:      []string{"sh", "-c", "cp /plugin.wasm /var/local/lib/wasm-filters/oidc.wasm"},
						VolumeMounts: []v12.VolumeMount{initContainerVolumeMount},
					}

					patches = append(patches, patchOperation{
						Op:    "add",
						Path:  "/spec/template/spec/volumes",
						Value: []v12.Volume{volumes},
					})

					patches = append(patches, patchOperation{
						Op:    "add",
						Path:  "/spec/template/spec/initContainers",
						Value: []v12.Container{initContainers},
					})

					//----------------------------
					// Add difficult patch data
					// in the specific containers
					//----------------------------
					for i, container := range statefulset.Spec.Template.Spec.Containers {
						if container.EnvFrom != nil {
							logger.Info().Msgf("envFrom in container %v exist", container.Name)
						} else {
							patches = append(patches, patchOperation{
								Op:    "add",
								Path:  "/spec/template/spec/containers/" + strconv.Itoa(i) + "/envFrom",
								Value: []v12.EnvFromSource{envFrom},
							})
						}

						if container.Lifecycle != nil {
							logger.Info().Msgf("livecycle in container %v exist", container.Name)
						} else {
							patches = append(patches, patchOperation{
								Op:    "add",
								Path:  "/spec/template/spec/containers/" + strconv.Itoa(i) + "/lifecycle",
								Value: livecycle,
							})
						}
					}

				}
			}
		}
	}

	return patches, nil
}
