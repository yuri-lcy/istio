package controller

import (
	"context"
	"fmt"
	"istio.io/istio/pilot/pkg/acmg"
	v1 "k8s.io/api/core/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/features"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/util/sets"
	"istio.io/pkg/env"
)

var autoLabel = env.RegisterBoolVar("ACMG_AUTO_LABEL", false, "").Get()

type AutoLabel struct {
	labeledNamespace []string
	podQueue         *controllers.Queue
	podLister        listerv1.PodLister
	client           kubelib.Client
}

func NewAutoLabel() *AutoLabel {
	return &AutoLabel{
		labeledNamespace: make([]string, 0),
	}
}

func (a *AutoLabel) nsOnAcmg(ns string) bool {
	if ns == "" {
		return false
	}
	for _, labelledNs := range a.labeledNamespace {
		if labelledNs == ns {
			return true
		}
	}
	return false
}

func (a *AutoLabel) initAutolabel(opts *Options) {
	if !autoLabel && !opts.forceAutoLabel {
		return
	}
	log.Infof("Starting acmg mesh auto-labeler")

	opts.Client.KubeInformer().Core().V1().Namespaces().Informer().AddEventHandler(a.labeledNamespaceInformer())

	podQueue := controllers.NewQueue("acmg pod label controller",
		controllers.WithReconciler(a.acmgPodLabelPatcher(opts.Client)),
		controllers.WithMaxAttempts(5),
	)
	a.podQueue = &podQueue
	a.client = opts.Client
	a.podLister = opts.Client.KubeInformer().Core().V1().Pods().Lister()

	ignored := sets.New(append(strings.Split(features.AcmgAutolabelIgnore, ","), opts.SystemNamespace)...)
	workloadHandler := controllers.FilteredObjectHandler(podQueue.AddObject, a.acmgPodLabelFilter(ignored))
	opts.Client.KubeInformer().Core().V1().Pods().Informer().AddEventHandler(workloadHandler)
	go a.podQueue.Run(opts.Stop)
}

var labelPatch = []byte(fmt.Sprintf(
	`[{"op":"add","path":"/metadata/labels/%s","value":"%s" }]`,
	acmg.LabelType,
	acmg.TypeWorkload,
))

func (a *AutoLabel) addPodToQueue(namespace interface{}) {
	ns := namespace.(*v1.Namespace)

	a.labeledNamespace = append(a.labeledNamespace, ns.Name)
	pods, err := a.podLister.Pods(ns.Name).List(klabels.Everything())
	if err != nil {
		log.Errorf("Failed to list namespaces %v pods %v", ns, err)
		return
	}
	for pod := range pods {
		a.podQueue.Add(pod)
	}
}

func checkNamespaceLabel(ns interface{}) bool {
	if labelValue, labelled := ns.(controllers.Object).GetLabels()["istio.io/dataplane-mode"]; labelled && labelValue == "acmg" {
		return true
	}
	return false
}

func (a *AutoLabel) labeledNamespaceInformer() *cache.ResourceEventHandlerFuncs {
	return &cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if checkNamespaceLabel(obj) {
				a.addPodToQueue(obj)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if checkNamespaceLabel(newObj) && !checkNamespaceLabel(oldObj) {
				a.addPodToQueue(newObj)
			}
			log.Infof("")
		},
		DeleteFunc: func(obj interface{}) {
			return
		},
	}
}

func (a *AutoLabel) acmgPodLabelFilter(ignoredNamespaces sets.String) func(o controllers.Object) bool {
	return func(o controllers.Object) bool {
		_, alreadyLabelled := o.GetLabels()[acmg.LabelType]
		ignored := inject.IgnoredNamespaces.Contains(o.GetNamespace()) || ignoredNamespaces.Contains(o.GetNamespace())
		_, injected := o.GetLabels()[label.SecurityTlsMode.Name]
		return !alreadyLabelled && !ignored && !injected && a.nsOnAcmg(o.GetNamespace())
	}
}

func (a *AutoLabel) acmgPodLabelPatcher(client kubelib.Client) func(types.NamespacedName) error {
	return func(key types.NamespacedName) error {
		_, err := client.Kube().CoreV1().
			Pods(key.Namespace).
			Patch(
				context.Background(),
				key.Name,
				types.JSONPatchType,
				labelPatch, metav1.PatchOptions{},
			)
		return err
	}
}
