package main

import (
	logger "github.com/rs/zerolog/log"
	"io"
	v1 "k8s.io/api/apps/v1"
	v12 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"os"
	"path/filepath"

	"flag"
	"strconv"

	"errors"
	"k8s.io/api/admission/v1beta1"

	"encoding/json"
	"github.com/rs/zerolog"
)

type ServerParameters struct {
	port     int    // webhook server port
	certFile string // path to the x509 certificate for https
	keyFile  string // path to the x509 private key matching `CertFile`
	logLevel string // level of logging
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

var parameters ServerParameters

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

var config *rest.Config
var clientSet *kubernetes.Clientset

func main() {

	useKubeConfig := os.Getenv("USE_KUBECONFIG")
	kubeConfigFilePath := os.Getenv("KUBECONFIG")

	flag.IntVar(&parameters.port, "port", 8443, "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.logLevel, "logLevel", "info", "Specify level of logging.")
	flag.Parse()

	switch parameters.logLevel {
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

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

	logger.Info().Msgf("Starting of API server... \n  Port: %v \t CertFile: %v \t KeyFile: %v \n",
		parameters.port, parameters.certFile, parameters.keyFile)

	http.HandleFunc("/mutate/deployments", HandleMutate)
	err = http.ListenAndServeTLS(":"+strconv.Itoa(parameters.port), parameters.certFile, parameters.keyFile, nil)
	logger.Error().Msg(err.Error())
}

func HandleMutate(w http.ResponseWriter, r *http.Request) {

	body, err := io.ReadAll(r.Body)
	logger.Debug().Msg(string(body[:]))
	logger.Debug().Msg("Writing request in /tmp/request")

	err = os.WriteFile("/tmp/request", body, 0644)
	if err != nil {
		panic(err.Error())
	}

	var admissionReviewReq v1beta1.AdmissionReview

	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReviewReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Error().Msgf("could not deserialize request: %v", err)
	} else if admissionReviewReq.Request == nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Error().Msg("malformed admission review: request is nil")
		err := errors.New("malformed admission review: request is nil")
		if err != nil {
			return
		}
	}

	logger.Info().Msgf("Type: %v \t Event: %v \t Name: %v \n",
		admissionReviewReq.Request.Kind,
		admissionReviewReq.Request.Operation,
		admissionReviewReq.Request.Name,
	)

	//var pod apiv1.Pod
	var deployment v1.Deployment

	err = json.Unmarshal(admissionReviewReq.Request.Object.Raw, &deployment)
	if err != nil {
		logger.Error().Msgf("could not unmarshal pod on admission request: %v", err)
	}

	patches := createPatch(&deployment)

	patchBytes, err := json.Marshal(patches)

	if err != nil {
		logger.Error().Msgf("could not marshal JSON patch: %v", err)
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
		logger.Error().Msgf("marshaling response: %v", err)
	}

	_, err = w.Write(bytes)
	if err != nil {
		return
	}

}

func createPatch(deployment *v1.Deployment) []patchOperation {
	var patches []patchOperation
	var labels = make(map[string]string)
	var annotations = make(map[string]string)

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

	for name := range deployment.Spec.Template.ObjectMeta.Labels {
		if name == "notebook-name" {

			labels["type-app"] = "notebook"
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/spec/template/metadata/labels",
				Value: labels,
			})

			annotations["sidecar.istio.io/componentLogLevel"] = "wasm:debug"
			annotations["sidecar.istio.io/userVolume"] = "[{\"name\":\"wasmfilters-dir\",\"emptyDir\": {}}]"
			annotations["sidecar.istio.io/userVolumeMount"] = "[{\"mountPath\":\"/var/local/lib/wasm-filters\",\"name\":\"wasmfilters-dir\"}]"
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/spec/template/metadata/annotations",
				Value: annotations,
			})

			for i, container := range deployment.Spec.Template.Spec.Containers {
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

			break
		}
	}

	return patches
}
