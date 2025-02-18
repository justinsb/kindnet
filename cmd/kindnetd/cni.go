// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"text/template"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	corev1 "k8s.io/api/core/v1"
	utilsnet "k8s.io/utils/net"
)

/* cni config management */

// CNIConfigInputs is supplied to the CNI config template
type CNIConfigInputs struct {
	PodCIDRs      []string
	RangeStart    []string
	DefaultRoutes []string
	Mtu           int
}

// ComputeCNIConfigInputs computes the template inputs for CNIConfigWriter
func ComputeCNIConfigInputs(node *corev1.Node) CNIConfigInputs {
	inputs := CNIConfigInputs{}
	podCIDRs, _ := utilsnet.ParseCIDRs(node.Spec.PodCIDRs) // already validated
	for _, podCIDR := range podCIDRs {
		inputs.PodCIDRs = append(inputs.PodCIDRs, podCIDR.String())
		// define the default route
		if utilsnet.IsIPv4CIDR(podCIDR) {
			inputs.DefaultRoutes = append(inputs.DefaultRoutes, "0.0.0.0/0")
		} else {
			inputs.DefaultRoutes = append(inputs.DefaultRoutes, "::/0")
		}
		// reserve the first IPs of the range
		size := utilsnet.RangeSize(podCIDR)
		podCapacity := node.Status.Capacity.Pods().Value()
		if podCapacity == 0 {
			podCapacity = 110 // default to 110
		}
		rangeStart := ""
		offset := size - podCapacity
		if offset > 10 { // reserve the first 10 addresses of the Pod range if there is capacity
			startAddress, err := utilsnet.GetIndexedIP(podCIDR, 10)
			if err == nil {
				rangeStart = startAddress.String()
			}
		}
		inputs.RangeStart = append(inputs.RangeStart, rangeStart)

	}
	return inputs
}

// GetMTU returns the MTU used for the IP family
func GetMTU(ipFamily int) (int, error) {
	iface, err := GetDefaultGwInterface(ipFamily)
	if err != nil {
		return 0, err
	}
	mtu, err := getInterfaceMTU(iface)
	if err != nil {
		return 0, err
	}
	return mtu, nil
}

// getInterfaceMTU finds the mtu for the interface
func getInterfaceMTU(iface string) (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, inter := range interfaces {
		if inter.Name == iface {
			return inter.MTU, nil
		}
	}
	return 0, fmt.Errorf("no %s device found", iface)
}

func GetDefaultGwInterface(ipFamily int) (string, error) {
	routes, err := netlink.RouteList(nil, ipFamily)
	if err != nil {
		return "", err
	}

	for _, r := range routes {
		// no multipath
		if len(r.MultiPath) == 0 {
			if r.Gw == nil {
				continue
			}
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				log.Printf("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			return intfLink.Attrs().Name, nil
		}

		// multipath, use the first valid entry
		// xref: https://github.com/vishvananda/netlink/blob/6ffafa9fc19b848776f4fd608c4ad09509aaacb4/route.go#L137-L145
		for _, nh := range r.MultiPath {
			if nh.Gw == nil {
				continue
			}
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				log.Printf("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			return intfLink.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("not routes found")
}

// cniConfigPath is where kindnetd will write the computed CNI config
const cniConfigPath = "/etc/cni/net.d/10-kindnet.conflist"

const cniConfigTemplate = `
{
	"cniVersion": "0.4.0",
	"name": "kindnet",
	"plugins": [
	{
		"type": "ptp",
		"ipMasq": false,
		"ipam": {
			"type": "host-local",
			"dataDir": "/run/cni-ipam-state",
			"routes": [
				{{- range $i, $route := .DefaultRoutes}}
				{{- if gt $i 0 }},{{end}}
				{ "dst": "{{ $route }}" }
				{{- end}}
			],
			"ranges": [
				{{- range $i, $cidr := .PodCIDRs}}
				{{- if gt $i 0 }},{{end}}
				[ { "subnet": "{{ $cidr }}" {{ if index $.RangeStart $i }}, "rangeStart": "{{ index $.RangeStart $i }}" {{ end -}} } ]
				{{- end}}
			]
		}
		{{if .Mtu}},
		"mtu": {{ .Mtu }}
		{{end}}
	},
	{
		"type": "portmap",
		"capabilities": {
			"portMappings": true
		}
	}
	]
}
`

const cniConfigTemplateBridge = `
{
	"cniVersion": "0.4.0",
	"name": "kindnet",
	"plugins": [
	{
		"type": "bridge",
		"bridge": "kind-br",
		"ipMasq": false,
		"isGateway": true,
		"isDefaultGateway": true,
		"hairpinMode": true,
		"ipam": {
			"type": "host-local",
			"dataDir": "/run/cni-ipam-state",
			"ranges": [
				{{- range $i, $cidr := .PodCIDRs}}
				{{- if gt $i 0 }},{{end}}
				[ { "subnet": "{{ $cidr }}" {{ if index $.RangeStart $i }}, "rangeStart": "{{ index $.RangeStart $i }}" {{ end -}} } ]
				{{- end}}
			]
		}
		{{- if .Mtu}},
		"mtu": {{ .Mtu }}
		{{- end}}
	},
	{
		"type": "portmap",
		"capabilities": {
			"portMappings": true
		}
	}
	]
}
`

// CNIConfigWriter no-ops re-writing config with the same inputs
// NOTE: should only be called from a single goroutine
type CNIConfigWriter struct {
	path       string
	lastInputs CNIConfigInputs
	mtu        int
	bridge     bool
}

// Write will write the config based on
func (c *CNIConfigWriter) Write(inputs CNIConfigInputs) error {
	if reflect.DeepEqual(inputs, c.lastInputs) {
		return nil
	}

	// use an extension not recognized by CNI to write the contents initially
	// https://github.com/containerd/go-cni/blob/891c2a41e18144b2d7921f971d6c9789a68046b2/opts.go#L170
	// then we can rename to atomically make the file appear
	f, err := os.Create(c.path + ".temp")
	if err != nil {
		return err
	}

	template := cniConfigTemplate
	if c.bridge {
		template = cniConfigTemplateBridge
	}

	// actually write the config
	if err := writeCNIConfig(f, template, inputs); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	_ = f.Sync()
	_ = f.Close()

	// then we can rename to the target config path
	if err := os.Rename(f.Name(), c.path); err != nil {
		return err
	}

	// we're safely done now, record the inputs
	c.lastInputs = inputs
	return nil
}

func writeCNIConfig(w io.Writer, rawTemplate string, data CNIConfigInputs) error {
	t, err := template.New("cni-json").Parse(rawTemplate)
	if err != nil {
		return errors.Wrap(err, "failed to parse cni template")
	}
	return t.Execute(w, &data)
}
