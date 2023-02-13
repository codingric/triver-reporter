package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type VulnerabilityReportList struct {
	Items []VulnerabilityReport
}

type VulnerabilityReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Report            Report `json:"report"`
}

type Report struct {
	Artifact        Artifact
	Registry        Registry
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         Summary
}

type Summary struct {
	Critical int `json:"criticalCount"`
	High     int `json:"highCount"`
	Low      int `json:"lowCount"`
	Medium   int `json:"mediumCount"`
	None     int `json:"noneCount"`
	Unknown  int `json:"unknownCount"`
}

type Registry struct {
	Server string
}

type Artifact struct {
	Repository string
	Tag        string
}

type Vulnerability struct {
	FixedVersion     string `json:"fixedVersion"`
	InstalledVersion string `json:"installedVersion"`
	//Links string `json:"links"`
	PrimaryLink     string  `json:"primaryLink"`
	Resource        string  `json:"resource"`
	Score           float32 `json:"score"`
	Severity        string  `json:"severity"`
	Target          string  `json:"target"`
	Title           string  `json:"title"`
	VulnerabilityID string  `json:"vulnerabilityID"`
}

func main() {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	var config *rest.Config
	var err error

	// use the current context in kubeconfig
	config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Error().Msg("Unable to load kubeconfig")
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to load InCluster config")
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to create clientset")
	}

	log.Info().Msg("Kubeconfig loaded")

	root_handler := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {

		type namespace struct {
			Name     string
			Reports  int
			Critical int
			High     int
			Medium   int
			Low      int
			Unknown  int
			None     int
		}

		nss, err := clientset.CoreV1().Namespaces().List(r.Context(), metav1.ListOptions{})
		if err != nil {
			log.Error().Msg("Unable to retrieve namespaces")
			w.WriteHeader(500)
			return
		}

		var data []namespace

		for _, ns := range nss.Items {
			url := fmt.Sprintf("/apis/aquasecurity.github.io/v1alpha1/namespaces/%s/vulnerabilityreports", ns.Name)

			payload, err := clientset.RESTClient().Get().AbsPath(url).DoRaw(r.Context())
			if err != nil {
				log.Error().Msg("Unable to retrieve reports")
				w.WriteHeader(500)
				return
			}
			var reports *VulnerabilityReportList
			if err := json.Unmarshal(payload, &reports); err != nil {
				log.Error().Msg("Failed to parse reports")
				w.WriteHeader(500)
				return
			}
			log.Trace().Int("reports", len(reports.Items)).Str("namespace", ns.Name).Send()

			if len(reports.Items) > 0 {

				datum := namespace{Name: ns.Name, Reports: len(reports.Items), Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0}
				for _, r := range reports.Items {

					datum.Critical += r.Report.Summary.Critical
					datum.High += r.Report.Summary.High
					datum.Medium += r.Report.Summary.Medium
					datum.Low += r.Report.Summary.Low
					datum.Unknown += r.Report.Summary.Unknown
					datum.None += r.Report.Summary.None
				}
				data = append(data, datum)
			}
		}

		t, err := template.ParseFiles("root.tpl")
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse template")
			w.WriteHeader(500)
			return
		}
		err = t.Execute(w, data)
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute template")
			w.WriteHeader(500)
			return
		}
	}

	reports_handler := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		ns := p.ByName("namespace")
		url := fmt.Sprintf("/apis/aquasecurity.github.io/v1alpha1/namespaces/%s/vulnerabilityreports", ns)

		payload, err := clientset.RESTClient().Get().AbsPath(url).DoRaw(context.TODO())
		if err != nil {
			log.Error().Msg("Unable to retrieve reports")
			w.WriteHeader(500)
			return
		}
		var reports *VulnerabilityReportList
		if err := json.Unmarshal(payload, &reports); err != nil {
			log.Error().Msg("Failed to parse report")
			w.WriteHeader(500)
			return
		}
		log.Trace().Int("reports", len(reports.Items)).Str("namespace", ns).Send()

		// Now let's unmarshall the data into `payload`
		type Report struct {
			Namespace string
			Name      string
			Image     string
			Critical  int
			High      int
			Medium    int
			Low       int
			Unknown   int
			None      int
		}
		type Reports struct {
			Namespace string
			Items     []Report
		}

		data := Reports{Namespace: ns, Items: make([]Report, len(reports.Items))}
		for i, r := range reports.Items {
			data.Items[i] = Report{
				Namespace: r.Namespace,
				Image:     r.Report.Artifact.Repository + ":" + r.Report.Artifact.Tag,
				Name:      r.Name,
				Critical:  r.Report.Summary.Critical,
				High:      r.Report.Summary.High,
				Medium:    r.Report.Summary.Medium,
				Low:       r.Report.Summary.Low,
				Unknown:   r.Report.Summary.Unknown,
				None:      r.Report.Summary.None,
			}
		}

		t, err := template.ParseFiles("reports.tpl")
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse template")
			w.WriteHeader(500)
			return
		}
		err = t.Execute(w, data)
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute template")
			w.WriteHeader(500)
			return
		}
	}

	report_handler := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		ns := p.ByName("namespace")
		name := p.ByName("name")
		url := fmt.Sprintf("/apis/aquasecurity.github.io/v1alpha1/namespaces/%s/vulnerabilityreports/%s", ns, name)

		payload, err := clientset.RESTClient().Get().AbsPath(url).DoRaw(context.TODO())
		if err != nil {
			log.Error().Msg("Unable to retrieve report")
			w.WriteHeader(500)
			return
		}
		var reports *VulnerabilityReportList
		if err := json.Unmarshal(payload, &reports); err != nil {
			log.Error().Msg("Failed to parse report")
			w.WriteHeader(500)
			return
		}
		log.Trace().Str("name", reports.Items[0].Name).Str("namespace", ns).Msg("Retrieved report successfully")
		t, err := template.ParseFiles("report.tpl")
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse template")
			w.WriteHeader(500)
			return
		}
		err = t.Execute(w, reports.Items[0])
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute template")
			w.WriteHeader(500)
			return
		}
	}

	router := httprouter.New()
	router.GET("/", root_handler)
	router.GET("/:namespace", reports_handler)
	router.GET("/:namespace/:image", report_handler)

	log.Info().Msg("Serving on port 8080...")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal().Err(err).Send()
	}
}
