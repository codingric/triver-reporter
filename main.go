package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
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

type UserClaims struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

var (
	provider        *oidc.Provider
	oauth2Config    oauth2.Config
	idTokenVerifier *oidc.IDTokenVerifier
	K8sClient       *kubernetes.Clientset
)

func main() {
	init_oidc()

	init_k8s()

	router := httprouter.New()
	router.GET("/", root_handler)
	router.GET("/callback", callback_handler)
	router.GET("/logout", logout_handler)
	router.GET("/n/:namespace", reports_handler)
	router.GET("/n/:namespace/i/:image", report_handler)

	log.Info().Msg("Serving on port 8080...")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal().Err(err).Send()
	}
}

type Logger struct {
	handler http.Handler
}

func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Info().Msgf("%s -- %s", r.Method, r.URL.Path)
	l.handler.ServeHTTP(w, r)
}

func init_k8s() {
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

	K8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to create clientset")
	}

	log.Info().Msg("Kubeconfig loaded")
}

func init_oidc() {
	log.Debug().Msgf("OIDC Endpoint: %s", os.Getenv("OIDC_ISSUER"))
	provider, e := oidc.NewProvider(context.TODO(), os.Getenv("OIDC_ISSUER"))
	if e != nil {
		log.Fatal().Err(e).Msg("Failed to create oidc provider")
	}

	oauth2Config = oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("%scallback", os.Getenv("ENDPOINT")),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	idTokenVerifier = provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})
}

func authorized(r *http.Request) (*UserClaims, error) {
	token, err := r.Cookie("trivy")
	if err != nil {
		return nil, fmt.Errorf("no bearer token found")
	}
	idToken, err := idTokenVerifier.Verify(r.Context(), token.Value)
	if err != nil {
		return nil, fmt.Errorf("could not verify bearer token: %v", err)
	}
	// Extract custom claims.
	var claims UserClaims

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}
	log.Info().Msgf("Claims: %v", claims)
	return &claims, nil
}

func logout_handler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	http.SetCookie(w, &http.Cookie{
		Name:    "trivy",
		Value:   "",
		Expires: time.Now(),
		MaxAge:  0,
	})
	t, err := template.ParseFiles("logout.tpl")
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse template")
		w.WriteHeader(500)
		return
	}
	err = t.Execute(w, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to execute template")
		w.WriteHeader(500)
		return
	}
}

func callback_handler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	url_ := p.ByName("state")

	oauth2Token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Error().Err(err).Msg("Failed OAuth exchange")
		w.WriteHeader(403)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Error().Err(err).Msg("Can't extract token")
		w.WriteHeader(500)
		return
	}

	// Parse and verify ID Token payload.
	idToken, err := idTokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Error().Err(err).Msg("Unable to verify token")
		w.WriteHeader(500)
		return
	}

	// Extract custom claims.
	var claims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Groups   []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Error().Err(err).Msg("Failed to extract claims")
		w.WriteHeader(500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "trivy",
		Value:   rawIDToken,
		Expires: time.Now().Add(2 * time.Hour),
	})
	http.Redirect(w, r, url_, http.StatusFound)
}

func report_handler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	user, err := authorized(r)
	if err != nil {
		http.Redirect(w, r, oauth2Config.AuthCodeURL(r.RequestURI), http.StatusFound)
		return
	}

	ns := p.ByName("namespace")
	name := p.ByName("name")
	url := fmt.Sprintf("/apis/aquasecurity.github.io/v1alpha1/namespaces/%s/vulnerabilityreports/%s", ns, name)

	payload, err := K8sClient.RESTClient().Get().AbsPath(url).DoRaw(context.TODO())
	if err != nil {
		log.Error().Msg("Unable to retrieve report")
		w.WriteHeader(500)
		return
	}
	type tmpl_data struct {
		Report    Report
		Username  string
		Namespace string
		Name      string
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
	data := tmpl_data{Username: user.Email, Report: reports.Items[0].Report, Namespace: ns, Name: name}
	err = t.Execute(w, data)
	if err != nil {
		log.Error().Err(err).Msg("Failed to execute template")
		w.WriteHeader(500)
		return
	}
}

func reports_handler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	user, err := authorized(r)
	if err != nil {
		http.Redirect(w, r, oauth2Config.AuthCodeURL(r.RequestURI), http.StatusFound)
		return
	}

	ns := p.ByName("namespace")
	url := fmt.Sprintf("/apis/aquasecurity.github.io/v1alpha1/namespaces/%s/vulnerabilityreports", ns)

	payload, err := K8sClient.RESTClient().Get().AbsPath(url).DoRaw(context.TODO())
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
		Username  string
	}

	data := Reports{Namespace: ns, Items: make([]Report, len(reports.Items)), Username: user.Email}
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

func root_handler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	user, err := authorized(r)
	if err != nil {
		http.Redirect(w, r, oauth2Config.AuthCodeURL(r.RequestURI), http.StatusFound)
		return
	}

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

	type tmpl_data struct {
		Username   string
		Namespaces []namespace
	}

	nss, err := K8sClient.CoreV1().Namespaces().List(r.Context(), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Unable to retrieve namespaces")
		w.WriteHeader(500)
		return
	}

	data := tmpl_data{Username: user.Email}

	for _, ns := range nss.Items {
		url := fmt.Sprintf("/apis/aquasecurity.github.io/v1alpha1/namespaces/%s/vulnerabilityreports", ns.Name)

		payload, err := K8sClient.RESTClient().Get().AbsPath(url).DoRaw(r.Context())
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
			data.Namespaces = append(data.Namespaces, datum)
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
