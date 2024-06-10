package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	extclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/aojea/kindnet/apis"
	kindnetclient "github.com/aojea/kindnet/apis/generated/clientset/versioned"
	configinformers "github.com/aojea/kindnet/apis/generated/informers/externalversions"
	"github.com/aojea/kindnet/pkg/apis/config/v1alpha1"
)

const (
	dsKindnetd    = "kindnetd"
	kindnetdImage = "ghcr.io/aojea/kindnetd:v1.1.0"
)

func main() {
	// enable logging
	klog.InitFlags(nil)
	_ = flag.Set("logtostderr", "true")

	flag.Parse()
	flag.VisitAll(func(flag *flag.Flag) {
		log.Printf("FLAG: --%s=%q", flag.Name, flag.Value)
	})

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	config.UserAgent = "kindnet-controller"
	crdConfig := config // shallow copy because  CRDs does not support proto
	// use protobuf for better performance at scale
	// https://kubernetes.io/docs/reference/using-api/api-concepts/#alternate-representations-of-resources
	// npaConfig := config // shallow copy because  CRDs does not support proto
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	crdClientset, err := kindnetclient.NewForConfig(crdConfig)
	if err != nil {
		panic(err.Error())
	}

	// creates the clientset for the APIExtensions CustomResourceDefinition
	extClientset, err := extclient.NewForConfig(crdConfig)
	if err != nil {
		panic(err.Error())
	}

	/*
		informersFactory := informers.NewSharedInformerFactory(clientset, 0)
		podInformer := informersFactory.Core().V1().Pods()
		nodeInformer := informersFactory.Core().V1().Nodes()
		serviceInformer := informersFactory.Core().V1().Services()
	*/

	err = apiextensionsv1.AddToScheme(scheme.Scheme)
	if err != nil {
		panic(err.Error())
	}
	decoder := scheme.Codecs.UniversalDeserializer()

	runtimeObject, _, err := decoder.Decode(apis.KindnetYamlCRD, nil, nil)
	if err != nil {
		panic(err.Error())
	}
	newCRD := runtimeObject.(*apiextensionsv1.CustomResourceDefinition)
	newCRDVersion := getCRDVersions(newCRD)
	// After CRD creation, it might take a few seconds for the RESTful API endpoint to be created.
	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(ctx context.Context) (bool, error) {
		var crd *apiextensionsv1.CustomResourceDefinition
		crd, err = extClientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, "configurations.kindnet.io", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				_, err = extClientset.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, newCRD, metav1.CreateOptions{})
				if err != nil {
					klog.Infof("unexpected error trying to create CRD: %v", err)
				}
				// wait until the CRD is Established
				return false, nil
			}
		}

		crdVersion := getCRDVersions(crd)
		// TODO be smarter, right now simply update always
		if !crdVersion.Equal(newCRDVersion) {
			klog.Infof("detected different versions between controller CRD and cluster CRD: %v", crdVersion.Difference(newCRDVersion))
			newCRD.ResourceVersion = crd.ResourceVersion
			crd, err = extClientset.ApiextensionsV1().CustomResourceDefinitions().Update(ctx, newCRD, metav1.UpdateOptions{})
			if err != nil {
				klog.Infof("unexpected error trying to create CRD: %v", err)
				return false, nil
			}
		}

		for _, c := range crd.Status.Conditions {
			if c.Type == apiextensionsv1.Established && c.Status == apiextensionsv1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		panic(err.Error())
	}

	crdFactory := configinformers.NewSharedInformerFactory(crdClientset, 0)
	configInfomer := crdFactory.Kindnet().V1alpha1().Configurations()
	configLister := configInfomer.Lister()
	crdFactory.Start(ctx.Done())

	if ok := cache.WaitForCacheSync(ctx.Done(), configInfomer.Informer().HasSynced); !ok {
		klog.Fatalf("caches not synced waiting for Kindnet Configuration")
	}

	var kindnetConfig *v1alpha1.Configuration
	err = wait.PollUntilContextCancel(ctx, 3*time.Second, true, func(ctx context.Context) (bool, error) {
		var err error
		kindnetConfig, err = configLister.Configurations("kube-system").Get("kindnet")
		if err != nil {
			klog.Info("Configuration not found, retrying ...")
			return false, nil
		}
		klog.Infof("starting kindnet with config:\n %+v", kindnetConfig)
		// TODO use conditions for more complex operations
		// if cr.Status.Conditions
		return true, nil
	})
	if err != nil {
		panic(err.Error())
	}

	image := kindnetdImage
	if kindnetConfig.Spec.KindnetdImage != "" {
		image = kindnetConfig.Spec.KindnetdImage
	}
	labels := map[string]string{
		"tier":    "node",
		"app":     "kindnetd",
		"k8s-app": "kindnetd",
	}

	ds := newDaemonSet(image, labels)
	_, err = clientset.AppsV1().DaemonSets("kube-system").Get(ctx, ds.Name, metav1.GetOptions{})
	// TODO check the error type
	if err != nil {
		_, err = clientset.AppsV1().DaemonSets("kube-system").Create(ctx, ds, metav1.CreateOptions{})
		if err != nil {
			klog.Infof("error creating service account %+v : %v", ds, err)
		}
	} else {
		_, err = clientset.AppsV1().DaemonSets("kube-system").Update(ctx, ds, metav1.UpdateOptions{})
		if err != nil {
			klog.Infof("error creating service account %+v : %v", ds, err)
		}
	}

	// wait until the daemonset has finished
	err = wait.PollUntilContextCancel(ctx, 3*time.Second, true, func(ctx context.Context) (bool, error) {
		ds, err := clientset.AppsV1().DaemonSets("kube-system").Get(ctx, dsKindnetd, metav1.GetOptions{})
		if err != nil {
			klog.Infof("error trying to get kindnetd daemonset: %v", err)
			return false, nil
		}
		desired, scheduled, ready := ds.Status.DesiredNumberScheduled, ds.Status.CurrentNumberScheduled, ds.Status.NumberReady
		if desired != scheduled && desired != ready {
			klog.Infof("error in daemon status. DesiredScheduled: %d, CurrentScheduled: %d, Ready: %d", desired, scheduled, ready)
			return false, nil
		}
		return true, nil
	})

	klog.Infof("kindnetd correctly started")

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
}

// TODO we may need to do more with the fields Served, Storage and Deprecated but
// right now just match if the versions are the same.
func getCRDVersions(crd *apiextensionsv1.CustomResourceDefinition) sets.Set[string] {
	if crd == nil {
		return nil
	}
	result := sets.New[string]()
	for _, version := range crd.Spec.Versions {
		result.Insert(version.Name)
	}
	return result
}

// TODO: add probes
func newDaemonSet(image string, labels map[string]string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:   dsKindnetd,
			Labels: labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: v1.PodSpec{
					HostNetwork:        true,
					ServiceAccountName: "kindnetd",
					PriorityClassName:  "system-node-critical",
					Tolerations: []v1.Toleration{{
						Operator: v1.TolerationOpExists,
						Effect:   v1.TaintEffectNoSchedule,
					}},
					InitContainers: []v1.Container{
						{
							Name:    "install-cni-bin",
							Image:   image,
							Command: []string{"sh", "-c", "cd /opt/cni/bin; for i in * ; do cat $i > /cni/$i ; chmod +x /cni/$i ; done"},
							VolumeMounts: []v1.VolumeMount{{
								Name:      "cni-bin",
								MountPath: "/cni",
							}},
						},
					},
					Containers: []v1.Container{
						{
							Name:  "kindnetd-cni",
							Image: image,
							VolumeMounts: []v1.VolumeMount{{
								Name:      "cni-cfg",
								MountPath: "/etc/cni/net.d",
							}},
							Resources: v1.ResourceRequirements{
								Requests: v1.ResourceList{
									v1.ResourceName(v1.ResourceCPU):    resource.MustParse("100m"),
									v1.ResourceName(v1.ResourceMemory): resource.MustParse("50Mi")},
							},
							SecurityContext: &v1.SecurityContext{
								Capabilities: &v1.Capabilities{
									Add: []v1.Capability{"NET_RAW", "NET_ADMIN"},
								},
							},
						},
					},
					SecurityContext: &v1.PodSecurityContext{},
					Volumes: []v1.Volume{{
						Name: "cni-bin",
						VolumeSource: v1.VolumeSource{
							HostPath: &v1.HostPathVolumeSource{
								Path: "/opt/cni/bin",
								Type: ptr.To(v1.HostPathDirectoryOrCreate),
							}},
					}, {
						Name: "cni-cfg",
						VolumeSource: v1.VolumeSource{
							HostPath: &v1.HostPathVolumeSource{
								Path: "/etc/cni/net.d",
								Type: ptr.To(v1.HostPathDirectoryOrCreate),
							}},
					}},
				},
			},
		},
	}
}
