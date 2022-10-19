//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSpec) DeepCopyInto(out *CertificateSpec) {
	*out = *in
	if in.IngressGateway != nil {
		in, out := &in.IngressGateway, &out.IngressGateway
		*out = new(IngressGatewayCertSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSpec.
func (in *CertificateSpec) DeepCopy() *CertificateSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalAuthzSpec) DeepCopyInto(out *ExternalAuthzSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalAuthzSpec.
func (in *ExternalAuthzSpec) DeepCopy() *ExternalAuthzSpec {
	if in == nil {
		return nil
	}
	out := new(ExternalAuthzSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FeatureFlags) DeepCopyInto(out *FeatureFlags) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FeatureFlags.
func (in *FeatureFlags) DeepCopy() *FeatureFlags {
	if in == nil {
		return nil
	}
	out := new(FeatureFlags)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressGatewayCertSpec) DeepCopyInto(out *IngressGatewayCertSpec) {
	*out = *in
	if in.SubjectAltNames != nil {
		in, out := &in.SubjectAltNames, &out.SubjectAltNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	out.Secret = in.Secret
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressGatewayCertSpec.
func (in *IngressGatewayCertSpec) DeepCopy() *IngressGatewayCertSpec {
	if in == nil {
		return nil
	}
	out := new(IngressGatewayCertSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfig) DeepCopyInto(out *MeshConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfig.
func (in *MeshConfig) DeepCopy() *MeshConfig {
	if in == nil {
		return nil
	}
	out := new(MeshConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfigList) DeepCopyInto(out *MeshConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MeshConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfigList.
func (in *MeshConfigList) DeepCopy() *MeshConfigList {
	if in == nil {
		return nil
	}
	out := new(MeshConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfigSpec) DeepCopyInto(out *MeshConfigSpec) {
	*out = *in
	in.Sidecar.DeepCopyInto(&out.Sidecar)
	in.Traffic.DeepCopyInto(&out.Traffic)
	out.Observability = in.Observability
	in.Certificate.DeepCopyInto(&out.Certificate)
	out.FeatureFlags = in.FeatureFlags
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfigSpec.
func (in *MeshConfigSpec) DeepCopy() *MeshConfigSpec {
	if in == nil {
		return nil
	}
	out := new(MeshConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ObservabilitySpec) DeepCopyInto(out *ObservabilitySpec) {
	*out = *in
	out.Tracing = in.Tracing
	out.RemoteLogging = in.RemoteLogging
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ObservabilitySpec.
func (in *ObservabilitySpec) DeepCopy() *ObservabilitySpec {
	if in == nil {
		return nil
	}
	out := new(ObservabilitySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RemoteLoggingSpec) DeepCopyInto(out *RemoteLoggingSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RemoteLoggingSpec.
func (in *RemoteLoggingSpec) DeepCopy() *RemoteLoggingSpec {
	if in == nil {
		return nil
	}
	out := new(RemoteLoggingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RemoteLoggingSpec) DeepCopyInto(out *RemoteLoggingSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RemoteLoggingSpec.
func (in *RemoteLoggingSpec) DeepCopy() *RemoteLoggingSpec {
	if in == nil {
		return nil
	}
	out := new(RemoteLoggingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarDriverSpec) DeepCopyInto(out *SidecarDriverSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarDriverSpec.
func (in *SidecarDriverSpec) DeepCopy() *SidecarDriverSpec {
	if in == nil {
		return nil
	}
	out := new(SidecarDriverSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarSpec) DeepCopyInto(out *SidecarSpec) {
	*out = *in
	if in.SidecarDrivers != nil {
		in, out := &in.SidecarDrivers, &out.SidecarDrivers
		*out = make([]SidecarDriverSpec, len(*in))
		copy(*out, *in)
	}
	in.Resources.DeepCopyInto(&out.Resources)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarSpec.
func (in *SidecarSpec) DeepCopy() *SidecarSpec {
	if in == nil {
		return nil
	}
	out := new(SidecarSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TracingSpec) DeepCopyInto(out *TracingSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TracingSpec.
func (in *TracingSpec) DeepCopy() *TracingSpec {
	if in == nil {
		return nil
	}
	out := new(TracingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TrafficSpec) DeepCopyInto(out *TrafficSpec) {
	*out = *in
	if in.OutboundIPRangeExclusionList != nil {
		in, out := &in.OutboundIPRangeExclusionList, &out.OutboundIPRangeExclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OutboundPortExclusionList != nil {
		in, out := &in.OutboundPortExclusionList, &out.OutboundPortExclusionList
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
	if in.InboundPortExclusionList != nil {
		in, out := &in.InboundPortExclusionList, &out.InboundPortExclusionList
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
	out.InboundExternalAuthorization = in.InboundExternalAuthorization
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TrafficSpec.
func (in *TrafficSpec) DeepCopy() *TrafficSpec {
	if in == nil {
		return nil
	}
	out := new(TrafficSpec)
	in.DeepCopyInto(out)
	return out
}
